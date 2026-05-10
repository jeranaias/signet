"""Tests for the streaming abort-frame contract (v0.1.6 A3).

The proxy's :meth:`signet.server.app.SignetApp._forward_stream` runs
INSPECTION-stage checks against every upstream chunk and, on a non-
allow result, aborts the stream with a structured SSE frame:

    data: {"signet_abort": true,
           "reason": "<reason>",
           "correlation_id": "<entry_id>",
           "stage": "inspection",
           "check": "<check_name>"}\\n\\n
    data: [DONE]\\n\\n

Coverage:

* clean stream — no abort frame, all chunks pass through
* INSPECTION block via ScopeDriftCheck (classification leak) —
  pre-leak chunks delivered, leaking chunk dropped, abort frame +
  ``[DONE]`` follow, audit row carries chunk_count
* INSPECTION block via TokenBudgetCheck-shaped stub — abort frame
  carries ``check`` (verbose) / omits it (strict)
* upstream malformed SSE / non-200 mid-handshake — abort frame
  with stable token ``"upstream_protocol_violation"``, audit row
  metadata captures upstream status + verbatim error detail
* upstream 5xx — abort frame names the upstream status; audit row
  notes the upstream status code
* shadow mode — INSPECTION non-allow result is recorded but no
  abort frame is emitted; the chunk passes through

Test harness: ``httpx.AsyncClient.stream`` is patched with a fake
async-context-manager that yields a configurable byte-chunk sequence
(or raises ``httpx.RemoteProtocolError`` to simulate a torn-down
upstream). No FastAPI is needed for the upstream side — the spec is
HTTP-shape rather than full-stack — and ASGITransport buys us nothing
beyond what a direct patch already gives.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.audit.backend import JsonlBackend
from signet.checks.scope_drift import ScopeDriftCheck
from signet.core.check import Check, CheckResult
from signet.core.context import ResponseContext
from signet.core.pipeline import Pipeline
from signet.core.stage import Stage
from signet.server.app import SignetApp
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Fake upstream
# ---------------------------------------------------------------------------


class _FakeStreamResponse:
    """Mimic the subset of ``httpx.Response`` that ``_forward_stream``
    actually uses inside the ``async with`` block.

    Specifically: ``status_code`` for the early-exit guard and
    ``aiter_bytes()`` for the per-chunk loop. Anything else is left
    deliberately unimplemented; if production code starts touching it,
    we want the test to fail loudly rather than silently coerce.
    """

    def __init__(
        self,
        chunks: list[bytes],
        *,
        status_code: int = 200,
        raise_mid_stream: type[BaseException] | None = None,
        raise_after_chunks: int = 0,
    ) -> None:
        self.status_code = status_code
        self._chunks = chunks
        self._raise_mid_stream = raise_mid_stream
        self._raise_after_chunks = raise_after_chunks

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for i, chunk in enumerate(self._chunks):
            if (
                self._raise_mid_stream is not None
                and i >= self._raise_after_chunks
            ):
                # httpx.RemoteProtocolError takes (message, request=...);
                # we don't have a real request handle so use a 1-arg form
                # supported by both 0.27 and 0.28+ shapes.
                raise self._raise_mid_stream("upstream tore down the stream")
            yield chunk
        # Allow the test to schedule a torn-down stream AFTER the
        # configured chunks have all been yielded (raise_after_chunks
        # equal to len(chunks)).
        if (
            self._raise_mid_stream is not None
            and self._raise_after_chunks >= len(self._chunks)
        ):
            raise self._raise_mid_stream("upstream tore down the stream")


class _FakeStreamCM:
    """Async context manager wrapper that returns a _FakeStreamResponse."""

    def __init__(self, response: _FakeStreamResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _FakeStreamResponse:
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


def _patch_upstream_stream(
    monkeypatch: pytest.MonkeyPatch,
    *,
    chunks: list[bytes] | None = None,
    status_code: int = 200,
    raise_mid_stream: type[BaseException] | None = None,
    raise_after_chunks: int = 0,
) -> None:
    """Patch ``httpx.AsyncClient.stream`` to return a configurable fake.

    Returns nothing; tests assert against the proxy's response.
    """

    def fake_stream(_self, _method, _url, **_kwargs):
        return _FakeStreamCM(
            _FakeStreamResponse(
                chunks=list(chunks or []),
                status_code=status_code,
                raise_mid_stream=raise_mid_stream,
                raise_after_chunks=raise_after_chunks,
            )
        )

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _make_app(
    pipeline: Pipeline,
    *,
    audit_log_path,
    strict_error_redaction: bool = False,
    shadow: bool = False,
) -> tuple[SignetApp, TestClient]:
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=audit_log_path,
        strict_error_redaction=strict_error_redaction,
        shadow=shadow,
    )
    app = SignetApp(config=config, pipeline=pipeline)
    return app, TestClient(app.app)


def _post_stream(client: TestClient, body: dict[str, Any], headers: dict[str, str] | None = None):
    """POST a streaming chat-completions request and return the raw response."""
    return client.post(
        "/v1/chat/completions",
        json={"stream": True, **body},
        headers=headers or {},
    )


def _split_sse(text: str) -> list[str]:
    """Split an SSE response body into individual ``data:`` payload strings.

    Returns the JSON-payload portion of each frame in order, including
    the literal ``"[DONE]"`` marker. Blank-line event boundaries are
    consumed.
    """
    out: list[str] = []
    for raw_event in text.split("\n\n"):
        for line in raw_event.splitlines():
            if line.startswith("data:"):
                payload = line[len("data:") :]
                if payload.startswith(" "):
                    payload = payload[1:]
                out.append(payload)
    return out


def _find_abort_frame(payloads: list[str]) -> dict[str, Any] | None:
    """Return the parsed signet_abort frame if present, else None."""
    for p in payloads:
        if p == "[DONE]":
            continue
        try:
            obj = json.loads(p)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("signet_abort") is True:
            return obj
    return None


# ---------------------------------------------------------------------------
# Stub INSPECTION checks for tests
# ---------------------------------------------------------------------------


class _TokenBudgetStubCheck(Check):
    """Block as soon as accumulated text exceeds a per-request char cap.

    Mirrors the spirit of TokenBudgetCheck's mid-stream behavior without
    pulling its full ADMISSION machinery; the goal is just a
    deterministic INSPECTION-stage block we can match the abort frame
    against.
    """

    name = "token_budget"
    stage = Stage.INSPECTION

    def __init__(self, *, char_cap: int = 40) -> None:
        self.char_cap = char_cap

    async def inspect_response_chunk(
        self, ctx: ResponseContext, _chunk: str
    ) -> CheckResult:
        if len(ctx.accumulated_text) > self.char_cap:
            return CheckResult.block(
                f"output exceeded budgeted chars ({self.char_cap})",
                budget_chars=self.char_cap,
            )
        return CheckResult.allow()


# ---------------------------------------------------------------------------
# Helper: shape OpenAI-style chunks
# ---------------------------------------------------------------------------


def _content_chunk(text: str) -> bytes:
    payload = {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "choices": [{"delta": {"content": text}}],
    }
    return f"data: {json.dumps(payload)}\n\n".encode()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCleanStream:
    """A 10-chunk happy-path stream passes through unchanged."""

    def test_no_abort_frame_emitted(self, monkeypatch, tmp_path) -> None:
        chunks = [_content_chunk(f"part-{i} ") for i in range(10)] + [
            b"data: [DONE]\n\n"
        ]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        _app, client = _make_app(Pipeline(checks=[]), audit_log_path=tmp_path / "audit.jsonl")
        r = _post_stream(client, {"model": "test", "messages": []})

        assert r.status_code == 200
        payloads = _split_sse(r.text)
        # All 10 content frames + the [DONE] sentinel.
        assert len(payloads) == 11
        assert payloads[-1] == "[DONE]"
        # No signet_abort frame present.
        assert _find_abort_frame(payloads) is None
        # Every original chunk's content is reproduced verbatim.
        for i in range(10):
            assert any(f"part-{i}" in p for p in payloads if p != "[DONE]")


class TestClassificationLeak:
    """ScopeDriftCheck blocks mid-stream on a classification marker."""

    @pytest.mark.parametrize("strict", [False, True])
    def test_leak_aborts_with_structured_frame(self, monkeypatch, tmp_path, strict) -> None:
        # Three pre-leak chunks, then a chunk containing "(S//NF)" which
        # ScopeDriftCheck blocks at INSPECTION.
        chunks = [
            _content_chunk("Briefing summary: "),
            _content_chunk("see references. "),
            _content_chunk("Note: "),
            _content_chunk("(S//NF) classified bit follows."),
            # An additional chunk that should NEVER be delivered because
            # the prior chunk triggered the abort.
            _content_chunk(" should not appear"),
            b"data: [DONE]\n\n",
        ]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
            strict_error_redaction=strict,
        )
        r = _post_stream(
            client,
            {"model": "test", "messages": [{"role": "user", "content": "go"}]},
            headers={"X-Classification": "UNCLASS"},
        )

        assert r.status_code == 200  # SSE handshake already shipped
        payloads = _split_sse(r.text)

        # Pre-leak chunks delivered.
        assert any("Briefing summary" in p for p in payloads)
        assert any("see references" in p for p in payloads)

        # Leaking chunk NOT delivered. Filter out the signet_abort
        # frame and the [DONE] sentinel — the marker may appear in the
        # abort frame's reason field in verbose mode (that's the
        # contract; the marker IS the policy explanation), but it must
        # NOT appear in any forwarded content frame.
        content_frames = [
            p for p in payloads
            if p != "[DONE]" and "signet_abort" not in p
        ]
        assert not any("(S//NF)" in p for p in content_frames)
        assert not any("classified bit follows" in p for p in content_frames)

        # No subsequent chunks delivered.
        assert not any("should not appear" in p for p in content_frames)

        # Abort frame is the structured contract shape.
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["signet_abort"] is True
        assert frame["stage"] == "inspection"
        assert frame.get("correlation_id")

        if strict:
            # Strict redaction: reason coarsened, check name omitted.
            assert frame["reason"] == "refused"
            assert "check" not in frame
        else:
            # Verbose: full reason, check name surfaced.
            assert frame["reason"] != "refused"
            assert "scope_drift" in frame.get("check", "")

        # Trailing [DONE] sentinel.
        assert payloads[-1] == "[DONE]"

        # Audit row captures partial state.
        entries = list(JsonlBackend(log).iter_entries())
        inspection_rows = [
            e for e in entries if e.check_name == "pipeline.inspection"
        ]
        assert len(inspection_rows) == 1
        meta = inspection_rows[0].metadata
        # 3 chunks delivered before the leaking one (chunk 4 was not).
        assert meta.get("chunks_delivered") == 3
        assert meta.get("chunk_count_at_abort") == 4
        assert meta.get("abort_stage") == "inspection"
        # Firing check name preserved in audit metadata even in strict
        # mode (chain is the source of truth for incident response).
        assert meta.get("_check_name") == "scope_drift"


class TestTokenBudget:
    """A budget-overflow INSPECTION block names the firing check."""

    @pytest.mark.parametrize("strict", [False, True])
    def test_budget_overshoot_aborts(self, monkeypatch, tmp_path, strict) -> None:
        # Each chunk delivers ~30 chars; budget is 40. Chunk 1 fits,
        # chunk 2 should overflow and trigger a block.
        chunks = [
            _content_chunk("A" * 30),
            _content_chunk("B" * 30),
            _content_chunk("C" * 30),
            b"data: [DONE]\n\n",
        ]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(
            Pipeline(checks=[_TokenBudgetStubCheck(char_cap=40)]),
            audit_log_path=log,
            strict_error_redaction=strict,
        )
        r = _post_stream(
            client,
            {"model": "test", "messages": [], "max_tokens": 10},
        )

        assert r.status_code == 200
        payloads = _split_sse(r.text)
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["signet_abort"] is True
        assert frame["stage"] == "inspection"
        if strict:
            assert frame["reason"] == "refused"
            assert "check" not in frame
        else:
            assert frame.get("check") == "token_budget"
            assert "budgeted" in frame["reason"] or "budget" in frame["reason"]

        # Audit row carries the firing check name.
        entries = list(JsonlBackend(log).iter_entries())
        inspection_rows = [
            e for e in entries if e.check_name == "pipeline.inspection"
        ]
        assert len(inspection_rows) == 1
        assert inspection_rows[0].metadata.get("_check_name") == "token_budget"


class TestUpstreamMalformed:
    """Upstream tears down the stream mid-flight → abort frame, clean close."""

    def test_remote_protocol_error_yields_abort_frame(
        self, monkeypatch, tmp_path
    ) -> None:
        # Two chunks succeed, then upstream raises RemoteProtocolError.
        chunks = [_content_chunk("clean "), _content_chunk("text")]
        _patch_upstream_stream(
            monkeypatch,
            chunks=chunks,
            raise_mid_stream=httpx.RemoteProtocolError,
            raise_after_chunks=2,
        )

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(Pipeline(checks=[]), audit_log_path=log)
        r = _post_stream(client, {"model": "test", "messages": []})

        assert r.status_code == 200
        payloads = _split_sse(r.text)

        # Pre-error chunks delivered.
        assert any("clean" in p for p in payloads)

        # Abort frame uses the stable token.
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "upstream_protocol_violation"
        assert frame["stage"] == "inspection"
        assert payloads[-1] == "[DONE]"

        # Audit row notes the failure.
        entries = list(JsonlBackend(log).iter_entries())
        upstream_rows = [
            e for e in entries if e.check_name == "pipeline.upstream"
        ]
        assert len(upstream_rows) == 1
        meta = upstream_rows[0].metadata
        assert meta.get("abort_stage") == "upstream"
        # Verbatim error detail is in the audit row's reason or metadata.
        assert "RemoteProtocolError" in upstream_rows[0].reason


class TestUpstream5xx:
    """Upstream returns 5xx mid-handshake → abort frame, audit row notes status."""

    def test_5xx_yields_abort_frame_with_status(self, monkeypatch, tmp_path) -> None:
        _patch_upstream_stream(monkeypatch, chunks=[], status_code=503)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(Pipeline(checks=[]), audit_log_path=log)
        r = _post_stream(client, {"model": "test", "messages": []})

        assert r.status_code == 200  # SSE handshake already shipped
        payloads = _split_sse(r.text)
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "upstream_protocol_violation"
        assert payloads[-1] == "[DONE]"

        entries = list(JsonlBackend(log).iter_entries())
        upstream_rows = [
            e for e in entries if e.check_name == "pipeline.upstream"
        ]
        assert len(upstream_rows) == 1
        meta = upstream_rows[0].metadata
        assert meta.get("upstream_status") == 503
        assert "503" in upstream_rows[0].reason


class TestShadowMode:
    """Shadow mode: INSPECTION non-allow results pass through, no abort frame."""

    def test_shadow_does_not_abort_inspection_block(
        self, monkeypatch, tmp_path
    ) -> None:
        chunks = [
            _content_chunk("Briefing summary: "),
            _content_chunk("(S//NF) classified marker."),
            _content_chunk(" tail"),
            b"data: [DONE]\n\n",
        ]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
            shadow=True,
        )
        r = _post_stream(
            client,
            {"model": "test", "messages": [{"role": "user", "content": "go"}]},
            headers={"X-Classification": "UNCLASS"},
        )

        assert r.status_code == 200

        # Handshake-time advertisement is set — F1 thread reaches the
        # streaming path.
        assert r.headers.get("X-Signet-Shadow-Inspection-Active") == "1"

        payloads = _split_sse(r.text)
        # All chunks delivered, including the would-have-blocked one.
        assert any("(S//NF)" in p for p in payloads)
        assert any("tail" in p for p in payloads)
        # No abort frame.
        assert _find_abort_frame(payloads) is None

        # Audit row captures the would-have-blocked decision with shadow=True.
        entries = list(JsonlBackend(log).iter_entries())
        shadow_rows = [
            e for e in entries
            if e.check_name == "pipeline.inspection"
            and e.metadata.get("shadow") is True
        ]
        assert len(shadow_rows) >= 1


class TestUpstreamGenericException:
    """v0.1.7 S3: non-httpx exceptions also produce a structured abort frame.

    The previous code's ``except (httpx.RemoteProtocolError, httpx.ReadError)``
    was too narrow — any other failure (RuntimeError from a misconfigured
    transport, ssl error subclasses, custom transport exceptions in a
    live bridge subclass) escaped into the StreamingResponse generator
    and the SDK saw an opaque hang instead of a parseable terminal frame.
    """

    def test_runtime_error_yields_upstream_exception_abort(
        self, monkeypatch, tmp_path
    ) -> None:
        chunks = [_content_chunk("clean ")]
        _patch_upstream_stream(
            monkeypatch,
            chunks=chunks,
            raise_mid_stream=RuntimeError,
            raise_after_chunks=1,
        )

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(Pipeline(checks=[]), audit_log_path=log)
        r = _post_stream(client, {"model": "test", "messages": []})

        assert r.status_code == 200
        payloads = _split_sse(r.text)
        # Pre-error chunk delivered.
        assert any("clean" in p for p in payloads)
        # Abort frame uses the new transport-reason token so SDKs can
        # split protocol violations from generic exceptions.
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "upstream_exception"
        assert frame["stage"] == "inspection"
        assert payloads[-1] == "[DONE]"

        # Audit row records the exception class + message for forensics.
        entries = list(JsonlBackend(log).iter_entries())
        upstream_rows = [
            e for e in entries if e.check_name == "pipeline.upstream"
        ]
        assert len(upstream_rows) == 1
        meta = upstream_rows[0].metadata
        assert meta.get("_exception_class") == "RuntimeError"
        assert meta.get("_exception_message")
        assert meta.get("abort_stage") == "upstream"
        # No tracing escapes the generator: the test would have raised
        # if the proxy had let the exception propagate.

    def test_strict_mode_preserves_upstream_exception_reason(
        self, monkeypatch, tmp_path
    ) -> None:
        """v0.1.7 S2: strict redaction preserves the transport reason
        (``upstream_exception``) so SDKs can branch on retry semantics."""
        chunks = [_content_chunk("hello")]
        _patch_upstream_stream(
            monkeypatch,
            chunks=chunks,
            raise_mid_stream=RuntimeError,
            raise_after_chunks=1,
        )

        _app, client = _make_app(
            Pipeline(checks=[]),
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        r = _post_stream(client, {"model": "test", "messages": []})
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        frame = _find_abort_frame(payloads)
        assert frame is not None
        # Strict normally coarsens to ``refused``; transport reasons
        # survive so the SDK can tell a retryable wire error from a
        # policy refusal.
        assert frame["reason"] == "upstream_exception"
        # Strict still drops the firing-check field for consistency
        # with policy-blocked aborts.
        assert "check" not in frame

    def test_strict_mode_preserves_protocol_violation_reason(
        self, monkeypatch, tmp_path
    ) -> None:
        """v0.1.7 S2: strict mode preserves ``upstream_protocol_violation``."""
        chunks = [_content_chunk("hello")]
        _patch_upstream_stream(
            monkeypatch,
            chunks=chunks,
            raise_mid_stream=httpx.RemoteProtocolError,
            raise_after_chunks=1,
        )

        _app, client = _make_app(
            Pipeline(checks=[]),
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        r = _post_stream(client, {"model": "test", "messages": []})
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "upstream_protocol_violation"
        assert "check" not in frame

    def test_strict_mode_coarsens_policy_block(
        self, monkeypatch, tmp_path
    ) -> None:
        """v0.1.7 S2 control: a policy block under strict still becomes
        ``refused`` — the transport-preservation rule does NOT leak
        check identity for policy decisions."""
        # Two chunks; second triggers a budget block.
        chunks = [
            _content_chunk("A" * 30),
            _content_chunk("B" * 30),
        ]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        _app, client = _make_app(
            Pipeline(checks=[_TokenBudgetStubCheck(char_cap=40)]),
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        r = _post_stream(client, {"model": "test", "messages": []})
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "refused"
        assert "check" not in frame


class TestClassificationLeakAfterPad:
    """v0.1.7 S1 coordination: a long benign prefix followed by a
    classification marker still aborts.

    This test guards the streaming-layer side of the S1 finding. The
    actual marker-detection lives in scope_drift (owned by Agent 1.1);
    the proxy side here only has to make sure the chunk text reaches
    ``inspect_response_chunk`` — the cap on ``accumulated_text`` does
    NOT silence inspection because ``_extract_sse_content`` returns
    the current chunk's content independently. If the chain is
    Agent 1.1 still has work to do, this test will fail and the
    coordination flag in the report will surface that.
    """

    def test_marker_after_long_prefix_blocks(
        self, monkeypatch, tmp_path
    ) -> None:
        # Pad with 50 chunks of benign filler then a leak.
        chunks = [
            _content_chunk("benign payload chunk " * 5)
            for _ in range(50)
        ]
        chunks.append(_content_chunk("(S//NF) classified marker"))
        chunks.append(_content_chunk(" must not appear"))
        chunks.append(b"data: [DONE]\n\n")
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
        )
        r = _post_stream(
            client,
            {"model": "test", "messages": [{"role": "user", "content": "go"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        # Forwarded content frames must NOT carry the marker, regardless
        # of how long the benign prefix was.
        content_frames = [
            p for p in payloads
            if p != "[DONE]" and "signet_abort" not in p
        ]
        assert not any("(S//NF)" in p for p in content_frames)
        assert not any("must not appear" in p for p in content_frames)
        # Abort frame fired.
        assert _find_abort_frame(payloads) is not None
