"""Integration: streaming abort-frame contract under bug-hunt-derived edges.

This file is the integration-tier counterpart of
``tests/unit/test_streaming.py``. The unit file covers the canonical
abort-frame shapes; this file pins the **bug-hunt findings** from the
v0.1.6 → v0.1.7 sprint so each repro becomes a permanent regression
gate, not a one-shot script under ``D:/tmp/signet-test``.

Findings re-pinned here:

* **S1** -- a long benign prefix followed by a classification marker
  must still abort. The accumulated-text cap on ``ResponseContext``
  must NOT silence per-chunk inspection.
* **S2** -- strict-mode redaction preserves transport reasons
  (``upstream_protocol_violation``, ``upstream_exception``,
  ``upstream_content_type_invalid``) so SDKs can branch retry vs.
  policy-refused.
* **S3** -- non-httpx exceptions also produce a structured abort
  frame. Prior to fix, only ``httpx.RemoteProtocolError`` /
  ``httpx.ReadError`` were caught, so a ``RuntimeError`` from a
  transport bridge escaped as an opaque hang.
* **S6** -- ``inspect_all_sse_lines=True`` opt-in inspects ``event:``
  / ``id:`` / ``retry:`` lines as well, so a creative upstream that
  ships classified text out-of-band on an event line cannot bypass
  the gate.
* **S7** -- a 200 OK upstream with a non-SSE Content-Type
  (``application/octet-stream`` etc.) aborts cleanly with the
  ``upstream_content_type_invalid`` token instead of streaming
  binary garbage straight to the client.

The streaming-test harness here uses the same fake upstream pattern
as ``tests/unit/test_streaming.py`` (patch ``httpx.AsyncClient.stream``
with an async-context-manager that yields a configurable byte sequence),
but lives under ``tests/integration/`` because the value is in pinning
the **end-to-end** behavior under realistic upstream shapes -- not in
the unit-level wiring of the abort frame.
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
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Fake upstream (mirrors tests/unit/test_streaming.py harness)
# ---------------------------------------------------------------------------


class _FakeStreamResponse:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        status_code: int = 200,
        raise_mid_stream: type[BaseException] | None = None,
        raise_after_chunks: int = 0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._chunks = chunks
        self._raise_mid_stream = raise_mid_stream
        self._raise_after_chunks = raise_after_chunks
        self.headers: dict[str, str] = headers if headers is not None else {
            "content-type": "text/event-stream"
        }

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for i, chunk in enumerate(self._chunks):
            if (
                self._raise_mid_stream is not None
                and i >= self._raise_after_chunks
            ):
                raise self._raise_mid_stream("upstream tore down the stream")
            yield chunk
        if (
            self._raise_mid_stream is not None
            and self._raise_after_chunks >= len(self._chunks)
        ):
            raise self._raise_mid_stream("upstream tore down the stream")


class _FakeStreamCM:
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
    headers: dict[str, str] | None = None,
) -> None:
    def fake_stream(_self, _method, _url, **_kwargs):
        return _FakeStreamCM(
            _FakeStreamResponse(
                chunks=list(chunks or []),
                status_code=status_code,
                raise_mid_stream=raise_mid_stream,
                raise_after_chunks=raise_after_chunks,
                headers=headers,
            )
        )

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


def _make_app(
    pipeline: Pipeline,
    *,
    audit_log_path,
    strict_error_redaction: bool = False,
    inspect_all_sse_lines: bool = False,
) -> tuple[SignetApp, TestClient]:
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=audit_log_path,
        strict_error_redaction=strict_error_redaction,
        inspect_all_sse_lines=inspect_all_sse_lines,
    )
    app = SignetApp(config=config, pipeline=pipeline)
    return app, TestClient(app.app)


def _post_stream(
    client: TestClient, body: dict[str, Any], headers: dict[str, str] | None = None
):
    return client.post(
        "/v1/chat/completions",
        json={"stream": True, **body},
        headers=headers or {},
    )


def _split_sse(text: str) -> list[str]:
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


def _content_chunk(text: str) -> bytes:
    payload = {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "choices": [{"delta": {"content": text}}],
    }
    return f"data: {json.dumps(payload)}\n\n".encode()


# ---------------------------------------------------------------------------
# S1 -- classification marker after a long pad still aborts
# ---------------------------------------------------------------------------


class TestClassificationLeakAfterPad:
    """A long benign prefix must NOT prevent inspection from firing on a
    later chunk that carries a classification marker."""

    def test_marker_after_50_pad_chunks_blocks(
        self, monkeypatch, tmp_path
    ) -> None:
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
        # Classified marker / sentinel must not appear in any forwarded
        # content frame.
        content_frames = [
            p for p in payloads
            if p != "[DONE]" and "signet_abort" not in p
        ]
        assert not any("(S//NF)" in p for p in content_frames)
        assert not any("must not appear" in p for p in content_frames)
        # Abort frame fired.
        assert _find_abort_frame(payloads) is not None


# ---------------------------------------------------------------------------
# S2 -- strict mode preserves transport reasons
# ---------------------------------------------------------------------------


class TestStrictPreservesUpstreamProtocolViolation:
    """Strict mode normally coarsens reasons to ``refused``, but
    transport reasons survive so SDKs can branch on retry vs.
    policy-refused."""

    def test_remote_protocol_error_survives_strict(
        self, monkeypatch, tmp_path
    ) -> None:
        _patch_upstream_stream(
            monkeypatch,
            chunks=[_content_chunk("hi")],
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
        frame = _find_abort_frame(_split_sse(r.text))
        assert frame is not None
        assert frame["reason"] == "upstream_protocol_violation"
        assert "check" not in frame  # strict still drops check identity


# ---------------------------------------------------------------------------
# S3 -- non-httpx exceptions become structured abort frames
# ---------------------------------------------------------------------------


class TestNonHttpxExceptionEmitsAbort:
    """A bare ``RuntimeError`` from a misconfigured transport must
    produce a structured abort frame, not an opaque hang or 500."""

    def test_runtime_error_yields_upstream_exception_token(
        self, monkeypatch, tmp_path
    ) -> None:
        _patch_upstream_stream(
            monkeypatch,
            chunks=[_content_chunk("clean ")],
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
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "upstream_exception"
        assert frame["stage"] == "inspection"
        assert payloads[-1] == "[DONE]"

        # Audit row records the exception class for forensics.
        entries = list(JsonlBackend(log).iter_entries())
        upstream_rows = [
            e for e in entries if e.check_name == "pipeline.upstream"
        ]
        assert len(upstream_rows) == 1
        assert upstream_rows[0].metadata.get("_exception_class") == "RuntimeError"


# ---------------------------------------------------------------------------
# S7 -- garbage upstream bytes on a non-SSE content-type are caught
# ---------------------------------------------------------------------------


class TestGarbageUpstreamBytesCaught:
    """Upstream returning binary garbage with a non-SSE Content-Type
    must abort with the ``upstream_content_type_invalid`` token rather
    than streaming the garbage straight to the client."""

    def test_octet_stream_aborts(self, monkeypatch, tmp_path) -> None:
        garbage = [b"\x00\x01\x02\x03" * 1024 for _ in range(20)]
        _patch_upstream_stream(
            monkeypatch,
            chunks=garbage,
            status_code=200,
            headers={"content-type": "application/octet-stream"},
        )
        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(Pipeline(checks=[]), audit_log_path=log)
        r = _post_stream(client, {"model": "test", "messages": []})
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["reason"] == "upstream_content_type_invalid"
        assert payloads[-1] == "[DONE]"
        # No content frames forwarded -- the binary garbage stayed in.
        content_frames = [
            p for p in payloads
            if p != "[DONE]" and "signet_abort" not in p
        ]
        assert content_frames == []


# ---------------------------------------------------------------------------
# S6 -- inspect_all_sse_lines opt-in catches event: line bypass
# ---------------------------------------------------------------------------


class TestInspectAllSseLinesCatchesEventLine:
    """v0.1.7 S6 opt-in: a creative upstream shipping a marker on an
    ``event:`` line is caught when ``inspect_all_sse_lines=True``.

    Default (False) preserves OpenAI-protocol semantics where only
    ``data:`` lines are content-bearing; the opt-in is for operators
    who want defense in depth against an upstream that smuggles text
    out-of-band.
    """

    def test_marker_in_event_line_caught_when_opt_in(
        self, monkeypatch, tmp_path
    ) -> None:
        # An SSE frame with both an event: line carrying the marker
        # AND a data: line so the parser doesn't reject the frame.
        smuggle = (
            b"event: (S//NF) leaked via event line\n"
            b"data: " + json.dumps({
                "id": "x",
                "object": "chat.completion.chunk",
                "choices": [{"delta": {"content": "benign"}}],
            }).encode() + b"\n\n"
        )
        chunks = [smuggle, b"data: [DONE]\n\n"]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
            inspect_all_sse_lines=True,
        )
        r = _post_stream(
            client,
            {"model": "test", "messages": [{"role": "user", "content": "go"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        # Marker text must NOT have been forwarded as data:.
        content_frames = [
            p for p in payloads
            if p != "[DONE]" and "signet_abort" not in p
        ]
        assert not any("(S//NF)" in p for p in content_frames)
        # Abort frame fired.
        frame = _find_abort_frame(payloads)
        assert frame is not None
        assert frame["stage"] == "inspection"

    def test_marker_in_event_line_passes_when_not_opt_in(
        self, monkeypatch, tmp_path
    ) -> None:
        """Default (False) preserves historical OpenAI semantics: event:
        lines aren't inspected. The marker reaches the client because
        the proxy treated only the data: line as content. This is the
        documented trade-off; the opt-in is the defense.

        Note: even though the inspector did not fire, the data: line
        carries only the benign body, so the smuggled marker shows up
        ONLY in the raw event: line, NOT in any forwarded data: payload.
        That is the operator-facing observable when default mode is in
        use; this test pins the contract so a future ``inspect_all`` =
        True-by-default flip is a deliberate, explicit change.
        """
        smuggle = (
            b"event: (S//NF) leaked via event line\n"
            b"data: " + json.dumps({
                "id": "x",
                "object": "chat.completion.chunk",
                "choices": [{"delta": {"content": "benign"}}],
            }).encode() + b"\n\n"
        )
        chunks = [smuggle, b"data: [DONE]\n\n"]
        _patch_upstream_stream(monkeypatch, chunks=chunks)

        log = tmp_path / "audit.jsonl"
        _app, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
            inspect_all_sse_lines=False,
        )
        r = _post_stream(
            client,
            {"model": "test", "messages": [{"role": "user", "content": "go"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 200
        payloads = _split_sse(r.text)
        # No abort frame in default mode -- the inspector did not fire
        # because the marker was on an event: line.
        assert _find_abort_frame(payloads) is None
        # No data: payload contains the marker.
        data_only = [p for p in payloads if p != "[DONE]"]
        assert not any("(S//NF)" in p for p in data_only)
