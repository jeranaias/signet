"""Unit tests for Round 4 hunt fixes.

Bug A: ``_forward_unary`` / ``_forward_stream`` previously passed
upstream 3xx redirect responses through to the client. The client
would then follow ``Location`` to whatever the upstream named, which
bypassed signet -- the followed request never re-entered the gate.
A hostile or misconfigured upstream could use this to silently steer
clients into an attacker-controlled host. Both forward paths now
write a ``pipeline.upstream`` audit row with
``_refusal_kind=upstream_redirect`` and refuse with a structured 502
(sync) or a structured SSE abort frame (streaming). The Location
header host is captured in the audit row but the path / query /
fragment are NEVER echoed back -- a raw redirect URL is a PII / SSRF
leak surface.

Bug B: deeply nested JSON request bodies tripped CPython's
``RecursionError`` inside ``json.loads`` (NOT a
``json.JSONDecodeError``), which escaped the existing 400 handler with
a generic "invalid JSON body" message. Operators had no signal that
nesting depth was the cause. The handler now pre-validates structural
depth via :func:`_exceeds_json_depth` and refuses with a structured
``{"signet": {"error": "json_too_deeply_nested", "max_depth": N}}``
400.

Wire-shape contract coverage:

* Sync 3xx → 502 + signet-shaped body, audit row, no raw Location in
  response.
* Streaming 3xx → SSE abort frame with ``reason=upstream_redirect``,
  audit row, no raw Location in response.
* Sync 3xx with userinfo Location → userinfo stripped (no creds leak).
* Sync 3xx with relative Location → ``upstream_location_host=null``.
* Deep-nested JSON → 400 with structured signet body + audit row.
* Helper: ``_exceeds_json_depth`` is correct around the boundary.
* Helper: ``_extract_redirect_host`` handles absolute / relative /
  malformed / userinfo / blank inputs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.audit.backend import JsonlBackend
from signet.checks import OwnerResolutionCheck
from signet.core.pipeline import Pipeline
from signet.server.app import (
    _MAX_JSON_DEPTH,
    SignetApp,
    _exceeds_json_depth,
    _extract_redirect_host,
)
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Shared harness mirroring the integration-test helper. Kept local so the
# unit tier doesn't reach across directories.
# ---------------------------------------------------------------------------


def _build_app(tmp_path: Path, *, strict: bool = False) -> tuple[Path, TestClient]:
    """Build a SignetApp with an audit log; return (log_path, client)."""
    log = tmp_path / "audit.jsonl"
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        upstream_label="test-upstream",
        allow_ephemeral_key=True,
        audit_log_path=log,
        strict_error_redaction=strict,
    )
    app = SignetApp(
        config=config,
        pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
    )
    return log, TestClient(app.app)


def _read_entries(log: Path) -> list[Any]:
    if not log.exists():
        return []
    return list(JsonlBackend(log).iter_entries())


def _post(client: TestClient) -> httpx.Response:
    return client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-Commit-Owner": "human:alice"},
    )


def _post_stream(client: TestClient) -> Any:
    return client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "test",
            "stream": True,
            "messages": [{"role": "user", "content": "hi"}],
        },
        headers={"X-Commit-Owner": "human:alice"},
    )


# ---------------------------------------------------------------------------
# Bug A -- 3xx upstream on the sync path
# ---------------------------------------------------------------------------


def _patch_sync_redirect(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status_code: int,
    location: str | None,
    body: bytes = b"<html>moved</html>",
) -> None:
    """Patch httpx.AsyncClient.post to return a fake 3xx response."""

    async def fake_post(_self, _url, **_kwargs):
        class FakeResp:
            pass

        FakeResp.status_code = status_code
        FakeResp.content = body
        hdrs: dict[str, str] = {"content-type": "text/html"}
        if location is not None:
            hdrs["location"] = location
        FakeResp.headers = hdrs

        def _raise_json(self=None):
            import json as _json

            raise _json.JSONDecodeError("redirect body is not json", "doc", 0)

        FakeResp.json = staticmethod(_raise_json)
        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


class TestBugASyncRedirect:
    """Sync forward path must refuse 3xx upstream with a structured 502."""

    def test_302_with_absolute_location_returns_signet_shaped_502(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _patch_sync_redirect(
            monkeypatch,
            status_code=302,
            location="https://evil.example.com/login?token=secret#frag",
        )
        log, client = _build_app(tmp_path)
        r = _post(client)

        assert r.status_code == 502
        body = r.json()
        assert "signet" in body
        sig = body["signet"]
        assert sig["error"] == "upstream_redirected"
        assert sig["upstream_status"] == 302
        assert sig["upstream_location_host"] == "evil.example.com"
        # Path / query / fragment never appear in the response.
        assert "/login" not in r.text
        assert "token=secret" not in r.text
        assert "frag" not in r.text
        # Raw upstream body never appears either.
        assert "<html>" not in r.text
        # Attribution headers still fire so the caller can identify
        # the gate and the upstream status.
        assert r.headers.get("X-Signet-Upstream") == "test-upstream"
        assert r.headers.get("X-Signet-Upstream-Status") == "302"

        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
        assert len(rows) == 1
        assert rows[0].decision.value == "block"
        assert rows[0].metadata["_refusal_kind"] == "upstream_redirect"
        assert rows[0].metadata["upstream_status"] == 302
        assert rows[0].metadata["upstream_location_host"] == "evil.example.com"

    @pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
    def test_each_3xx_status_is_blocked(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        status_code: int,
    ) -> None:
        _patch_sync_redirect(
            monkeypatch,
            status_code=status_code,
            location="https://elsewhere.example.com/",
        )
        log, client = _build_app(tmp_path)
        r = _post(client)

        assert r.status_code == 502
        sig = r.json()["signet"]
        assert sig["error"] == "upstream_redirected"
        assert sig["upstream_status"] == status_code

        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
        assert len(rows) == 1
        assert rows[0].metadata["_refusal_kind"] == "upstream_redirect"

    def test_relative_location_surfaces_null_host(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Relative Location → host is null in the response body.

        A relative redirect means "go back to me" -- we can't name a
        new host. Surface ``null`` so the body shape stays stable
        without echoing a path component.
        """
        _patch_sync_redirect(
            monkeypatch,
            status_code=307,
            location="/login?next=/v1/chat",
        )
        log, client = _build_app(tmp_path)
        r = _post(client)

        assert r.status_code == 502
        sig = r.json()["signet"]
        assert sig["upstream_location_host"] is None
        # The relative path must not leak either.
        assert "/login" not in r.text
        assert "next=" not in r.text

        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
        assert rows[0].metadata["upstream_location_host"] is None

    def test_userinfo_stripped_from_location_host(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A ``user:pass@host`` Location must NOT leak the userinfo.

        Some upstreams forward inbound auth into the redirect URL by
        accident. Stripping the userinfo portion is mandatory.
        """
        _patch_sync_redirect(
            monkeypatch,
            status_code=302,
            location="https://alice:hunter2@victim.example.com/",
        )
        _log, client = _build_app(tmp_path)
        r = _post(client)

        sig = r.json()["signet"]
        assert sig["upstream_location_host"] == "victim.example.com"
        assert "alice" not in r.text
        assert "hunter2" not in r.text

    def test_missing_location_surfaces_null_host(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _patch_sync_redirect(monkeypatch, status_code=302, location=None)
        _log, client = _build_app(tmp_path)
        r = _post(client)
        assert r.status_code == 502
        sig = r.json()["signet"]
        assert sig["upstream_status"] == 302
        assert sig["upstream_location_host"] is None


# ---------------------------------------------------------------------------
# Bug A -- 3xx upstream on the streaming path
# ---------------------------------------------------------------------------


def _patch_stream_redirect(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status_code: int,
    location: str | None,
) -> None:
    """Patch httpx.AsyncClient.stream to return a fake 3xx response."""
    from contextlib import asynccontextmanager

    class FakeStream:
        def __init__(self) -> None:
            self.status_code = status_code
            hdrs: dict[str, str] = {"content-type": "text/html"}
            if location is not None:
                hdrs["location"] = location
            self.headers = hdrs

        async def aiter_bytes(self):  # pragma: no cover -- not reached
            yield b""

    @asynccontextmanager
    async def fake_stream(_self, _method, _url, **_kwargs):
        yield FakeStream()

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


class TestBugAStreamRedirect:
    """Streaming forward path must emit a structured abort on 3xx."""

    def test_302_emits_upstream_redirect_abort_frame(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _patch_stream_redirect(
            monkeypatch,
            status_code=302,
            location="https://evil.example.com/handoff?token=ABC",
        )
        log, client = _build_app(tmp_path)
        with _post_stream(client) as r:
            assert r.status_code == 200  # SSE handshake completes
            body = b"".join(r.iter_bytes())

        # Structured abort frame on the wire.
        assert b"signet_abort" in body
        assert b"upstream_redirect" in body
        assert b"[DONE]" in body
        # Raw Location URL components MUST NOT appear in the frame.
        assert b"evil.example.com" not in body
        assert b"/handoff" not in body
        assert b"token=ABC" not in body

        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
        assert len(rows) == 1
        row = rows[0]
        assert row.decision.value == "block"
        assert row.metadata["_refusal_kind"] == "upstream_redirect"
        assert row.metadata["upstream_status"] == 302
        # Audit row DOES carry the host for forensics; only the wire
        # frame is redacted.
        assert row.metadata["upstream_location_host"] == "evil.example.com"

    def test_relative_stream_redirect_surfaces_null_host_in_audit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _patch_stream_redirect(
            monkeypatch,
            status_code=307,
            location="/login",
        )
        log, client = _build_app(tmp_path)
        with _post_stream(client) as r:
            body = b"".join(r.iter_bytes())
        assert b"upstream_redirect" in body

        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
        assert rows[0].metadata["upstream_location_host"] is None
        # Even the relative path must not appear in the SSE frames.
        assert b"/login" not in body

    def test_strict_mode_preserves_upstream_redirect_token(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Strict-error-redaction must NOT coarsen ``upstream_redirect``
        to ``refused`` -- it is a transport-level token SDKs need to
        differentiate from a policy refusal in order to surface the
        redirect-target host to operators."""
        _patch_stream_redirect(
            monkeypatch,
            status_code=302,
            location="https://evil.example.com/",
        )
        log, client = _build_app(tmp_path, strict=True)
        with _post_stream(client) as r:
            body = b"".join(r.iter_bytes())
        assert b"upstream_redirect" in body
        assert b"refused" not in body

        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
        assert rows[0].metadata["_refusal_kind"] == "upstream_redirect"


# ---------------------------------------------------------------------------
# Bug A -- helper: _extract_redirect_host
# ---------------------------------------------------------------------------


class TestExtractRedirectHost:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("https://evil.example.com/", "evil.example.com"),
            ("https://evil.example.com/login?x=1#z", "evil.example.com"),
            ("http://host:8080/", "host:8080"),
            ("//evil.example.com/path", "evil.example.com"),
            ("/login", None),
            ("", None),
            ("   ", None),
            (None, None),
            ("https://alice:pw@victim.example.com/", "victim.example.com"),
            # Userinfo without password also stripped.
            ("https://alice@victim.example.com/", "victim.example.com"),
        ],
    )
    def test_extraction_matrix(self, raw: str | None, expected: str | None) -> None:
        assert _extract_redirect_host(raw) == expected


# ---------------------------------------------------------------------------
# Bug B -- deep-nested JSON returns structured error
# ---------------------------------------------------------------------------


def _make_deep_json(depth: int) -> bytes:
    """Build a JSON array literal nested ``depth`` levels deep."""
    return b"[" * depth + b"1" + b"]" * depth


class TestBugBDeepJson:
    def test_deep_nesting_returns_structured_400(self, tmp_path: Path) -> None:
        log, client = _build_app(tmp_path)
        raw = _make_deep_json(_MAX_JSON_DEPTH + 5)
        r = client.post(
            "/v1/chat/completions",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Commit-Owner": "human:alice",
            },
        )
        assert r.status_code == 400
        body = r.json()
        # Round 11 ``json_too_deeply_nested-envelope-shape-
        # inconsistency`` closure: the legacy ``{"signet": {...}}``
        # envelope was flattened to match every other preflight 400.
        # ``error`` and ``correlation_id`` are now top-level; the
        # ``max_depth`` hint is preserved (verbose mode only via
        # ``verbose_extras``) and moved to the same top level. SDKs
        # branching on ``body["error"]`` no longer raise ``KeyError``
        # on this one refusal kind.
        assert body["error"] == "json_too_deeply_nested"
        assert body["max_depth"] == _MAX_JSON_DEPTH
        assert "correlation_id" in body
        # The misleading legacy message MUST NOT be present.
        assert "invalid JSON" not in r.text

        # Audit chain captures the refusal so dashboards can alert on
        # the new ``_refusal_kind``.
        rows = [e for e in _read_entries(log) if e.check_name == "pipeline.preflight"]
        assert len(rows) == 1
        assert rows[0].metadata["_refusal_kind"] == "json_too_deeply_nested"
        assert rows[0].metadata["max_depth"] == _MAX_JSON_DEPTH

    def test_shallow_nesting_still_parses(self, tmp_path: Path) -> None:
        """A legitimately-deep but under-limit body must NOT be refused.

        Boundary regression: don't be over-eager and accidentally block
        a body that happens to nest, say, 10 levels deep (tool-call
        args, vision content arrays, etc.).
        """
        _log, client = _build_app(tmp_path)
        # 10-level-deep array inside the body's ``deep`` field is well
        # under the 64-level ceiling and should reach the upstream
        # client. We don't patch the upstream here so the post will
        # error past the parser gate -- we just need to confirm it's
        # not the 400 we're testing for.
        deep_value: Any = "leaf"
        for _ in range(10):
            deep_value = [deep_value]
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": "test",
                "messages": [
                    {"role": "user", "content": "hi"},
                ],
                "metadata": {"deep": deep_value},
            },
            headers={"X-Commit-Owner": "human:alice"},
        )
        # 400 with the deep-json signature would be a false positive.
        if r.status_code == 400:
            assert "json_too_deeply_nested" not in r.text

    def test_non_object_body_still_400_with_legacy_shape(self, tmp_path: Path) -> None:
        """Other 400 paths (non-object body) must NOT regress to the
        new deep-json shape -- only the genuine depth violation gets
        the structured signet error."""
        _log, client = _build_app(tmp_path)
        r = client.post(
            "/v1/chat/completions",
            content=b"[1,2,3]",
            headers={
                "Content-Type": "application/json",
                "X-Commit-Owner": "human:alice",
            },
        )
        assert r.status_code == 400
        # Round 9 ``preflight-error-label-inconsistency``: ``error``
        # is now a stable snake_case token, ``description`` carries
        # the human text. Audit consumers branch on the token.
        body = r.json()
        assert body.get("error") == "non_object_body"
        assert body.get("description") == "request body must be a JSON object"

    def test_invalid_json_syntax_still_returns_legacy_message(self, tmp_path: Path) -> None:
        _log, client = _build_app(tmp_path)
        r = client.post(
            "/v1/chat/completions",
            content=b"this is not json",
            headers={
                "Content-Type": "application/json",
                "X-Commit-Owner": "human:alice",
            },
        )
        assert r.status_code == 400
        # Round 9 ``preflight-error-label-inconsistency``: ``error``
        # is a stable token; the prose moved to ``description``.
        body = r.json()
        assert body["error"] == "json_decode_error"
        assert "invalid JSON" in body["description"]


# ---------------------------------------------------------------------------
# Bug B -- helper: _exceeds_json_depth scanner
# ---------------------------------------------------------------------------


class TestExceedsJsonDepth:
    def test_below_limit_returns_false(self) -> None:
        assert _exceeds_json_depth(b"[" * 5 + b"1" + b"]" * 5) is False

    def test_at_limit_returns_false(self) -> None:
        raw = b"[" * _MAX_JSON_DEPTH + b"1" + b"]" * _MAX_JSON_DEPTH
        assert _exceeds_json_depth(raw) is False

    def test_one_over_limit_returns_true(self) -> None:
        raw = b"[" * (_MAX_JSON_DEPTH + 1) + b"1" + b"]" * (_MAX_JSON_DEPTH + 1)
        assert _exceeds_json_depth(raw) is True

    def test_brackets_inside_strings_dont_count(self) -> None:
        """A string literal containing brackets must NOT bump depth.

        Closed-form: 65 ``[`` inside a string == depth 1 outer array.
        """
        bracket_str = b'"' + (b"[" * (_MAX_JSON_DEPTH + 1)) + b'"'
        raw = b"[" + bracket_str + b"]"
        assert _exceeds_json_depth(raw) is False

    def test_escaped_quote_inside_string_keeps_string_open(self) -> None:
        """``\\"`` inside a string does not close the string."""
        # String contains an escaped quote then a bunch of brackets.
        # If the scanner mishandles the escape it will treat the string
        # as closed and count the brackets toward depth.
        inner = b'\\"' + (b"[" * (_MAX_JSON_DEPTH + 1)) + b'\\"'
        bracket_str = b'"' + inner + b'"'
        raw = b"[" + bracket_str + b"]"
        assert _exceeds_json_depth(raw) is False

    def test_empty_body_returns_false(self) -> None:
        assert _exceeds_json_depth(b"") is False

    def test_mixed_object_array_nesting(self) -> None:
        """Nesting depth counts ``{`` and ``[`` equally."""
        raw = b"{" + b"[" * _MAX_JSON_DEPTH + b"1" + b"]" * _MAX_JSON_DEPTH + b"}"
        # Total depth is _MAX_JSON_DEPTH + 1 (the outer object).
        assert _exceeds_json_depth(raw) is True
