"""Round 7 hunt -- server-side regression tests.

Coverage map (one test class per finding in
``D:/tmp/signet-hunt-round7/findings/server.md``):

* ``TestInvalidUtf8Body`` -- P0 ``invalid-utf8-body-500-no-audit``
* ``TestNonDictUpstreamJson`` -- HIGH ``non-dict-upstream-json-crash``
* ``TestPreflightBodyShape`` -- MED
  ``preflight-400-leaks-detail-and-omits-correlation-id``
* ``TestGetOnUnknownV1Path`` -- MED
  ``get-on-v1-anything-returns-misleading-405``
* ``TestSessionIdLength`` -- MED ``unbounded-session-id-length``
* ``TestTrailingSlashEndpoints`` -- LOW
  ``unsupported-v1-trailing-slash-confusion``
* ``TestSessionIdControlChars`` -- LOW
  ``null-bytes-in-session-id-accepted``

All tests use the in-process ``TestClient`` and an HMAC audit log so
the audit-row invariant is verifiable.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    *,
    strict_error_redaction: bool = False,
    upstream_json: Any = None,
    upstream_status: int = 200,
) -> tuple[SignetApp, TestClient, Any]:
    """Build a SignetApp with an audit log and an optional fake upstream.

    When ``upstream_json`` is provided, ``httpx.AsyncClient.post`` is
    monkeypatched to return that JSON. Useful for the
    non-dict-upstream-json-crash tests.
    """

    captured: dict[str, Any] = {}

    if upstream_json is not _UNSET:

        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = upstream_status
                content = b""
                headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

                @staticmethod
                def json() -> Any:
                    return upstream_json

            captured["called"] = True
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    log = tmp_path / "audit.jsonl"
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=log,
        strict_error_redaction=strict_error_redaction,
    )
    app = SignetApp(config=config, pipeline=Pipeline(checks=[]))
    return app, TestClient(app.app), log


_UNSET = object()


def _audit_entries(log_path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# P0 -- invalid-utf8-body-500-no-audit
# ---------------------------------------------------------------------------


class TestInvalidUtf8Body:
    """Non-UTF-8 inbound JSON now routes through the preflight refusal
    helper (signet-shaped 400 + audit row + correlation_id) instead of
    raising UnicodeDecodeError into a bare 500."""

    @pytest.mark.parametrize(
        ("payload", "label"),
        [
            (bytes([0xFF, 0xFE, 0xFD]), "raw_high_bytes"),
            ('"caf\xe9"'.encode("latin-1"), "latin1_string"),
            (b"\x80\x81\x82\x83", "invalid_continuation"),
        ],
        ids=["raw_high_bytes", "latin1_string", "invalid_continuation"],
    )
    def test_invalid_encoding_returns_signet_shaped_400_with_audit_row(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        payload: bytes,
        label: str,
    ) -> None:
        _, client, log = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        r = client.post(
            "/v1/chat/completions",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400, f"{label}: status was {r.status_code}"
        body = r.json()
        # Signet-shaped 400: must carry ``error`` and ``correlation_id``.
        assert "error" in body
        assert "correlation_id" in body
        # Audit row present and tagged with the new ``invalid_encoding``
        # discriminator.
        rows = _audit_entries(log)
        kinds = {r["metadata"].get("_refusal_kind") for r in rows}
        assert "invalid_encoding" in kinds
        # Correlation matches the audit row.
        entry_ids = {r["entry_id"] for r in rows}
        assert body["correlation_id"] in entry_ids

    def test_invalid_encoding_audit_row_for_all_three_endpoints(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        _, client, log = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        # 3+ bytes starting with 0xFF triggers UTF-16 BOM detection in
        # json.loads and a real UnicodeDecodeError mid-decode. Two
        # bytes is too short and falls through to JSONDecodeError.
        payload = bytes([0xFF, 0xFE, 0xFD])
        for path in (
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
        ):
            r = client.post(
                path,
                content=payload,
                headers={"Content-Type": "application/json"},
            )
            assert r.status_code == 400
            assert "correlation_id" in r.json()
        rows = _audit_entries(log)
        # One row per call, all tagged invalid_encoding.
        assert (
            sum(1 for row in rows if row["metadata"].get("_refusal_kind") == "invalid_encoding")
            == 3
        )


# ---------------------------------------------------------------------------
# HIGH -- non-dict-upstream-json-crash
# ---------------------------------------------------------------------------


class TestNonDictUpstreamJson:
    @pytest.mark.parametrize(
        "upstream_payload",
        [
            [],  # top-level array
            None,  # top-level null
            "hi",  # top-level string
            42,  # top-level scalar
            {"choices": "x"},  # choices is a string
            {"choices": [1, 2, 3]},  # choices is a list of non-dicts
        ],
    )
    def test_502_with_upstream_protocol_violation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        upstream_payload: Any,
    ) -> None:
        _, client, log = _make_app(monkeypatch, tmp_path, upstream_json=upstream_payload)
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": "x",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        assert r.status_code == 502
        body = r.json()
        # Signet-shaped upstream failure body: ``error`` + correlation
        # + refusal_kind discriminator (verbose mode is on by default
        # in _make_app).
        assert body.get("error") == "upstream forward failed"
        assert body.get("refusal_kind") == "upstream_protocol_violation"
        assert "correlation_id" in body

        # Audit row tagged ``pipeline.upstream``, not the generic
        # ``pipeline.forward`` exception path.
        rows = _audit_entries(log)
        check_names = {row["check_name"] for row in rows}
        assert "pipeline.upstream" in check_names
        # Refusal kind matches.
        kinds = {
            row["metadata"].get("_refusal_kind")
            for row in rows
            if row["check_name"] == "pipeline.upstream"
        }
        assert "upstream_protocol_violation" in kinds


# ---------------------------------------------------------------------------
# MED -- preflight-400-leaks-detail-and-omits-correlation-id
# ---------------------------------------------------------------------------


class TestPreflightBodyShape:
    """Preflight 400 paths now honor strict_error_redaction and always
    carry ``correlation_id``."""

    @pytest.mark.parametrize(
        ("payload", "expected_error_substring"),
        [
            (b"", "empty"),
            (b'"just a string"', "object"),
            (b"not json at all", "invalid"),
            (b'{"x": NaN}', "non-finite"),
        ],
    )
    def test_strict_mode_redacts_verbose_extras_but_keeps_correlation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        payload: bytes,
        expected_error_substring: str,
    ) -> None:
        _, client, log = _make_app(
            monkeypatch,
            tmp_path,
            upstream_json=_UNSET,
            strict_error_redaction=True,
        )
        r = client.post(
            "/v1/chat/completions",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        # correlation_id always present.
        assert "correlation_id" in body
        # ``error`` present.
        assert "error" in body
        # Strict mode coarsens the body: no verbose hint fields.
        # The three forbidden leaks from the finding:
        assert "got_type" not in body
        assert "expected" not in body
        assert "max_depth" not in body
        # Audit row exists.
        rows = _audit_entries(log)
        assert any("_refusal_kind" in row["metadata"] for row in rows)

    def test_verbose_mode_keeps_hints_and_carries_correlation(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        _, client, log = _make_app(
            monkeypatch,
            tmp_path,
            upstream_json=_UNSET,
            strict_error_redaction=False,
        )
        r = client.post(
            "/v1/chat/completions",
            content=b'"just a string"',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        # Verbose: hint fields are present.
        assert body.get("got_type") == "str"
        assert "expected" in body
        # correlation_id still present in verbose mode.
        assert "correlation_id" in body
        rows = _audit_entries(log)
        entry_ids = {row["entry_id"] for row in rows}
        assert body["correlation_id"] in entry_ids


# ---------------------------------------------------------------------------
# MED -- get-on-v1-anything-returns-misleading-405
# ---------------------------------------------------------------------------


class TestGetOnUnknownV1Path:
    def test_get_and_post_unknown_v1_return_same_404_shape(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        _, client, _ = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        r_get = client.get("/v1/no-such-endpoint")
        r_post = client.post("/v1/no-such-endpoint", json={})
        assert r_get.status_code == r_post.status_code == 404
        # Both bodies must carry the same shape (error + endpoint + note).
        for r in (r_get, r_post):
            body = r.json()
            assert "not implemented" in body["error"]
            assert body["endpoint"] == "/v1/no-such-endpoint"

    def test_get_on_registered_endpoint_still_returns_405(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        _, client, _ = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        # GET on a registered POST endpoint is still a 405; that path
        # IS implemented, just not for GET.
        r = client.get("/v1/chat/completions")
        assert r.status_code == 405
        body = r.json()
        assert body["error"] == "method not allowed"


# ---------------------------------------------------------------------------
# MED -- unbounded-session-id-length
# ---------------------------------------------------------------------------


class TestSessionIdLength:
    def test_oversize_session_id_refused_with_audit_row(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        _, client, log = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        huge_sid = "x" * 64_000
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": "x",
                "messages": [{"role": "user", "content": "hi"}],
            },
            headers={"X-Signet-Session": huge_sid},
        )
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "session_id_too_long"
        assert "correlation_id" in body
        rows = _audit_entries(log)
        kinds = {row["metadata"].get("_refusal_kind") for row in rows}
        assert "session_id_too_long" in kinds

    def test_in_limit_session_id_accepted(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

                @staticmethod
                def json() -> dict[str, Any]:
                    return {"choices": [{"message": {"content": "ok"}}]}

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        _, client, _ = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        sid = "session-" + "a" * 100  # well under the 256-byte cap
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": "x",
                "messages": [{"role": "user", "content": "hi"}],
            },
            headers={"X-Signet-Session": sid},
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# LOW -- unsupported-v1-trailing-slash-confusion
# ---------------------------------------------------------------------------


class TestTrailingSlashEndpoints:
    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chat/completions/",
            "/v1/completions/",
            "/v1/embeddings/",
        ],
    )
    def test_trailing_slash_handled_identically(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        path: str,
    ) -> None:
        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

                @staticmethod
                def json() -> dict[str, Any]:
                    return {
                        "choices": [
                            {
                                "message": {"content": "hi"},
                                "text": "hi",
                                "finish_reason": "stop",
                            }
                        ],
                        "data": [{"embedding": [0.1]}],
                        "usage": {"total_tokens": 1},
                    }

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        _, client, _ = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        # Build a body acceptable to all three endpoints.
        if "embeddings" in path:
            payload = {"model": "x", "input": "hi"}
        else:
            payload = {
                "model": "x",
                "messages": [{"role": "user", "content": "hi"}],
            }
        r = client.post(path, json=payload)
        # The trailing-slash alias must route to the real handler,
        # not the catch-all 404.
        assert r.status_code == 200, f"got {r.status_code} body={r.text}"


# ---------------------------------------------------------------------------
# LOW -- null-bytes-in-session-id-accepted
# ---------------------------------------------------------------------------


class TestSessionIdControlChars:
    @pytest.mark.parametrize(
        "sid",
        [
            "foo\x00bar",
            "line1\nline2",
            "x\ty",
            "abc def",  # space
            "with;semicolons",
        ],
    )
    def test_control_chars_in_session_id_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, sid: str
    ) -> None:
        _, client, log = _make_app(monkeypatch, tmp_path, upstream_json=_UNSET)
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": "x",
                "messages": [{"role": "user", "content": "hi"}],
            },
            headers={"X-Signet-Session": sid},
        )
        # Spaces and other illegal characters either get stripped by
        # the wire layer or rejected here; in both cases the body
        # never contains the offending characters in the response.
        # We assert the request was refused with the expected shape
        # OR (if the wire layer dropped it as a header-injection
        # protection) returned 400 with an upstream-side guard.
        assert r.status_code == 400, f"got {r.status_code} body={r.text}"
        body = r.json()
        assert body["error"] == "session_id_invalid_charset"
        assert "correlation_id" in body
        rows = _audit_entries(log)
        kinds = {row["metadata"].get("_refusal_kind") for row in rows}
        assert "session_id_invalid_charset" in kinds
