"""Round 7 hunt -- streaming-side regression tests.

Coverage map (one test class per finding in
``D:/tmp/signet-hunt-round7/findings/streaming.md``):

* ``TestSseChunkBoundaryBypass`` -- P0 ``sse-chunk-boundary-bypass``
* ``TestSseToolCallArgsInspected`` -- HIGH ``sse-tool-call-args-uninspected``
* ``TestSseNonContentFieldsInspected`` -- HIGH
  ``sse-non-content-fields-uninspected``
* ``TestSseNonUtf8ContentAborts`` -- MED
  ``sse-non-utf8-content-forwarded-unscanned``
* ``TestSseStreamChunkSizeBound`` -- MED ``sse-stream-chunk-no-size-bound``
* ``TestSseMalformedEventCounted`` -- LOW
  ``sse-malformed-event-silently-dropped``

Tests reuse the same patched ``httpx.AsyncClient.stream`` shape that
``test_streaming.py`` uses; the test harness lives there.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.checks.regex_content import Pattern, RegexOutputCheck
from signet.checks.scope_drift import ScopeDriftCheck
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Patching helpers (mirrored from test_streaming.py so this file is
# self-contained)
# ---------------------------------------------------------------------------


class _FakeStreamResponse:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._chunks = chunks
        self.headers: dict[str, str] = (
            headers if headers is not None else {"content-type": "text/event-stream"}
        )

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


class _FakeStreamCM:
    def __init__(self, r: _FakeStreamResponse) -> None:
        self._r = r

    async def __aenter__(self) -> _FakeStreamResponse:
        return self._r

    async def __aexit__(self, *_a: Any) -> None:
        return None


def _patch_stream(
    monkeypatch: pytest.MonkeyPatch,
    chunks: list[bytes],
    *,
    headers: dict[str, str] | None = None,
) -> None:
    def fake_stream(_self, _method, _url, **_kwargs):
        return _FakeStreamCM(_FakeStreamResponse(chunks, headers=headers))

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


def _make_app(
    pipeline: Pipeline,
    audit_log_path,
    *,
    inspect_all_sse_lines: bool = False,
) -> tuple[SignetApp, TestClient]:
    cfg = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=audit_log_path,
        strict_error_redaction=False,
        inspect_all_sse_lines=inspect_all_sse_lines,
    )
    app = SignetApp(config=cfg, pipeline=pipeline)
    return app, TestClient(app.app)


def _post_stream(client: TestClient) -> Any:
    return client.post(
        "/v1/chat/completions",
        json={
            "stream": True,
            "model": "test",
            "messages": [{"role": "user", "content": "go"}],
        },
        headers={"X-Classification": "UNCLASS"},
    )


def _find_abort(text: str) -> dict[str, Any] | None:
    for raw_event in text.split("\n\n"):
        for line in raw_event.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[len("data:") :].lstrip(" ")
            if payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("signet_abort") is True:
                return obj
    return None


def _audit_rows(log_path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# P0 -- sse-chunk-boundary-bypass
# ---------------------------------------------------------------------------


class TestSseChunkBoundaryBypass:
    """A ``data:`` line split across chunks must still be inspected."""

    def _content_frames(self, text: str) -> list[str]:
        """Extract the list of upstream-content SSE frames seen by the
        client, ignoring the signet abort frame whose reason field
        legitimately echoes the marker in verbose mode."""
        out: list[str] = []
        for raw_event in text.split("\n\n"):
            for line in raw_event.splitlines():
                if not line.startswith("data:"):
                    continue
                payload = line[len("data:") :].lstrip(" ")
                if payload == "[DONE]":
                    continue
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    out.append(payload)
                    continue
                if isinstance(obj, dict) and obj.get("signet_abort") is True:
                    continue
                out.append(payload)
        return out

    def test_classification_marker_split_across_chunks_blocks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        # The S//NF marker straddles the chunk boundary. Pre-fix, each
        # chunk was stateless-parsed and the marker never landed in
        # ``accumulated_text``; post-fix the _SSEBuffer holds the
        # partial line until the terminator arrives.
        chunk1 = b'data: {"choices":[{"delta":{"content":"hello (S//'
        chunk2 = b'NF) classified leak"}}]}\n\ndata: [DONE]\n\n'
        _patch_stream(monkeypatch, [chunk1, chunk2])

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
        )
        r = _post_stream(client)

        assert r.status_code == 200  # SSE handshake committed
        # The abort frame must be present.
        abort = _find_abort(r.text)
        assert abort is not None, f"no abort frame; body={r.text!r}"
        # The classified marker must not appear in any upstream-content
        # frame that reaches the client. (The abort frame's ``reason``
        # field may legitimately echo the marker in verbose mode -- that
        # is a signet-generated diagnostic, not upstream content.)
        content_frames = self._content_frames(r.text)
        for frame in content_frames:
            assert "(S//NF)" not in frame, f"upstream content frame leaked the marker: {frame!r}"
        # Audit row tagged inspection.
        rows = _audit_rows(log)
        decisions = [(row["check_name"], row["decision"]) for row in rows]
        assert any(name == "pipeline.inspection" and dec == "block" for name, dec in decisions), (
            f"no inspection block row; rows={decisions}"
        )

    def test_regex_marker_split_at_byte_boundary_blocks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        # SSN pattern split across boundaries -- the same shape as the
        # P0 repro at repro_split_regex.py.
        chunk1 = b'data: {"choices":[{"delta":{"content":"my ssn 123-'
        chunk2 = b'45-6789 here"}}]}\n\ndata: [DONE]\n\n'
        _patch_stream(monkeypatch, [chunk1, chunk2])

        log = tmp_path / "audit.jsonl"
        pat = Pattern(
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            action="block",
            label="ssn",
        )
        _, client = _make_app(
            Pipeline(checks=[RegexOutputCheck([pat])]),
            audit_log_path=log,
        )
        r = _post_stream(client)

        assert r.status_code == 200
        abort = _find_abort(r.text)
        assert abort is not None, f"no abort frame; body={r.text!r}"
        # No upstream-content frame should carry the SSN.
        for frame in self._content_frames(r.text):
            assert "123-45-6789" not in frame, f"upstream content frame leaked the SSN: {frame!r}"

    def test_one_byte_per_chunk_split(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        # Pathological: every byte of a known leaking SSE event is its
        # own raw chunk. The buffer must still re-assemble correctly.
        full = (
            b'data: {"choices":[{"delta":{"content":"prefix '
            b'(S//NF) classified leak"}}]}\n\n'
            b"data: [DONE]\n\n"
        )
        chunks = [bytes([b]) for b in full]
        _patch_stream(monkeypatch, chunks)

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
        )
        r = _post_stream(client)

        assert r.status_code == 200
        # We MUST see an abort frame; no upstream-content frame may
        # carry the full marker.
        assert _find_abort(r.text) is not None
        for frame in self._content_frames(r.text):
            assert "(S//NF)" not in frame, f"upstream content frame leaked the marker: {frame!r}"


# ---------------------------------------------------------------------------
# HIGH -- sse-tool-call-args-uninspected
# ---------------------------------------------------------------------------


class TestSseToolCallArgsInspected:
    def test_tool_call_arguments_containing_marker_blocks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        # Tool args carry the classified marker; pre-fix this slipped
        # through because _extract_sse_content only read delta.content.
        chunk = (
            b'data: {"choices":[{"delta":{"tool_calls":[{"function":'
            b'{"name":"send_email","arguments":"to: alice (S//NF) hi"}'
            b"}]}}]}\n\ndata: [DONE]\n\n"
        )
        _patch_stream(monkeypatch, [chunk])

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        abort = _find_abort(r.text)
        assert abort is not None, f"tool args bypass: no abort frame; body={r.text!r}"

    def test_tool_call_function_name_pattern_blocks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        # The function name itself can carry sensitive content too.
        chunk = (
            b'data: {"choices":[{"delta":{"tool_calls":[{"function":'
            b'{"name":"BANNED_TOOL","arguments":"{}"}}]}}]}\n\n'
            b"data: [DONE]\n\n"
        )
        _patch_stream(monkeypatch, [chunk])
        log = tmp_path / "audit.jsonl"
        pat = Pattern(
            pattern=r"BANNED_TOOL",
            action="block",
            label="banned_tool",
        )
        _, client = _make_app(
            Pipeline(checks=[RegexOutputCheck([pat])]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert _find_abort(r.text) is not None


# ---------------------------------------------------------------------------
# HIGH -- sse-non-content-fields-uninspected
# ---------------------------------------------------------------------------


class TestSseNonContentFieldsInspected:
    @pytest.mark.parametrize(
        "field",
        ["refusal", "reasoning", "reasoning_content"],
    )
    def test_delta_text_field_inspected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        field: str,
    ) -> None:
        payload = {"choices": [{"delta": {field: "I cannot reveal (S//NF) markers"}}]}
        chunk = f"data: {json.dumps(payload)}\n\ndata: [DONE]\n\n".encode()
        _patch_stream(monkeypatch, [chunk])

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        abort = _find_abort(r.text)
        assert abort is not None, f"{field}: no abort frame; body={r.text!r}"

    def test_audio_transcript_inspected(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        payload = {"choices": [{"delta": {"audio": {"transcript": "leaking (S//NF) audio"}}}]}
        chunk = f"data: {json.dumps(payload)}\n\ndata: [DONE]\n\n".encode()
        _patch_stream(monkeypatch, [chunk])

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[ScopeDriftCheck()]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert _find_abort(r.text) is not None


# ---------------------------------------------------------------------------
# MED -- sse-non-utf8-content-forwarded-unscanned
# ---------------------------------------------------------------------------


class TestSseNonUtf8ContentAborts:
    def test_non_utf8_chunk_terminates_stream_with_signet_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        # Inject raw bytes that cannot decode as UTF-8.
        bad_chunk = b'data: {"choices":[{"delta":{"content":"\xff\xfe"}}]}\n\n'
        _patch_stream(monkeypatch, [bad_chunk])

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        abort = _find_abort(r.text)
        assert abort is not None, f"non-UTF-8 chunk silently forwarded; body={r.text!r}"
        assert abort["reason"] == "upstream_protocol_violation"
        # Audit row exists.
        rows = _audit_rows(log)
        upstream_rows = [row for row in rows if row["check_name"] == "pipeline.upstream"]
        assert upstream_rows, "no pipeline.upstream audit row"


# ---------------------------------------------------------------------------
# MED -- sse-stream-chunk-no-size-bound
# ---------------------------------------------------------------------------


class TestSseStreamChunkSizeBound:
    def test_huge_single_chunk_aborts_cleanly(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        # 2 MiB chunk; the cap is 1 MiB so this should abort.
        huge = b"data: " + b"x" * (2 * 1024 * 1024) + b"\n\n"
        _patch_stream(monkeypatch, [huge])

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        abort = _find_abort(r.text)
        assert abort is not None, f"oversize chunk forwarded; body[:200]={r.text[:200]!r}"
        assert abort["reason"] == "upstream_protocol_violation"


# ---------------------------------------------------------------------------
# LOW -- sse-malformed-event-silently-dropped
# ---------------------------------------------------------------------------


class TestSseMalformedEventCounted:
    def test_malformed_event_aborts_stream(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        # Round 9 ``sse-unparseable-json-event-leaks-raw-bytes``
        # closure: an event whose assembled ``data:`` payload fails
        # JSON parse now aborts the stream via
        # ``upstream_sse_malformed`` so the raw bytes (which had
        # already been collected for forwarding) cannot leak to the
        # client. Pre-Round-9 behavior was to silently increment
        # ``dropped_frame_count`` and forward the bytes verbatim,
        # which let a hostile upstream smuggle text past INSPECTION
        # by appending a garbage ``data:`` line. The audit row's
        # ``check_name`` changed from ``pipeline.complete``
        # (allow + dropped_frame_count) to ``pipeline.upstream``
        # (block).
        chunks = [
            b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n',
            b"data: this is not json\n\n",
            b'data: {"choices":[{"delta":{"content":" world"}}]}\n\n',
            b"data: [DONE]\n\n",
        ]
        _patch_stream(monkeypatch, chunks)

        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            Pipeline(checks=[]),
            audit_log_path=log,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        # The malformed-event abort emits an abort frame so SDKs see
        # a parseable terminal event rather than a hang.
        abort = _find_abort(r.text)
        assert abort is not None, f"malformed event did not abort; body[:300]={r.text[:300]!r}"
        assert abort["reason"] == "upstream_sse_malformed"
        # Audit row records the failure mode.
        rows = _audit_rows(log)
        upstream_rows = [row for row in rows if row["check_name"] == "pipeline.upstream"]
        assert upstream_rows, f"no pipeline.upstream row; rows={rows}"
