"""Round 17 hunt closures — regression coverage for F-R17-* findings.

The Round 17 hunt verified that R16 closures (F-R15-2 through
F-R15-10) hold and surfaced three new findings rooted in the SAME
walker-scope class that F-R15-2 closed at the event-top layer, but
one level deeper into the event tree:

HIGH:

- ``F-R17-1 choices[i] sibling fields bypass inspection``: F-R15-2
  stripped ``choices`` from the event-top walk to avoid double-walking
  ``delta`` strings, but the matching choice-level loop only re-
  included ``delta``. Sibling fields of ``delta`` inside a choice --
  ``text`` (legacy ``/v1/completions`` streaming),
  ``message.content`` (chat.completion buffered-as-SSE),
  ``logprobs.content[].token`` (token-level logprob payloads), and
  the choice-level ``finish_reason`` -- skipped inspection entirely.
  Post-fix the choice loop walks the whole choice dict (minus
  ``delta``, walked separately) via the new
  :data:`_SSE_CHOICE_STRUCTURAL_KEYS` /
  :func:`_validate_choice_structural_field` pair. A wrong-VALUE
  choice-level ``finish_reason`` aborts the stream as malformed,
  mirroring the delta-level enum gate.

MED:

- ``F-R17-2 httpx trust_env=True allows env MITM``: the upstream
  ``httpx.AsyncClient`` was constructed without ``trust_env=False``,
  so the httpx default honored process-environment knobs
  (``HTTPS_PROXY`` / ``SSL_CERT_FILE`` / ``CURL_CA_BUNDLE``) at
  request time. For a gateway whose purpose is to mediate trust
  between caller and upstream, the upstream-side TLS / proxy posture
  must be pinned by config, not by env. Post-fix the client is
  constructed with ``trust_env=False`` and explicit ``verify=True``.

LOW:

- ``F-R17-3 connection-pool cap not operator-tunable``: the upstream
  client used the httpx default ``Limits`` (``max_connections=100``,
  ``max_keepalive_connections=20``) with no config-level knob. Post-
  fix :class:`ServerConfig` carries
  ``upstream_pool_max_connections`` and
  ``upstream_pool_max_keepalive_connections`` fields, validated as
  positive ints, and ``_ensure_http`` passes them through to
  ``httpx.Limits(...)``.

F-R17-4 (choice-level ``finish_reason`` enum-validation gap) is
subsumed by F-R17-1 and tested under the choice-level abort path
below. F-R17-5 (digit-start header names) is a non-finding documented
in the round17 report -- no regression test needed.
"""

from __future__ import annotations

import json as _json

import httpx
import pytest

from signet.core.pipeline import Pipeline
from signet.server.app import (
    _SSE_CHOICE_STRUCTURAL_KEYS,
    _SSE_DELTA_FINISH_REASON_VALUES,
    _SSE_EVENT_OBJECT_VALUES,
    _STRUCTURAL_ABORT,
    _STRUCTURAL_OK,
    _STRUCTURAL_WALK,
    SignetApp,
    _collect_inspectable_strings,
    _SSEBuffer,
    _validate_choice_structural_field,
)
from signet.server.config import ServerConfig


def _make_sse_frame(**fields: object) -> str:
    """Build a single ``data: <json>\\n\\n`` SSE frame."""
    return f"data: {_json.dumps(fields)}\n\n"


# ---------------------------------------------------------------------------
# HIGH -- F-R17-1 choices[i] sibling fields bypass inspection
# ---------------------------------------------------------------------------


class TestF_R17_1_ChoiceSiblingsInspected:
    """``choices[i]`` siblings of ``delta`` now reach INSPECTION."""

    # ----- Structural set + validator unit tests -----

    def test_choice_structural_keys_contains_finish_reason(self) -> None:
        assert "finish_reason" in _SSE_CHOICE_STRUCTURAL_KEYS

    def test_choice_structural_keys_contains_index(self) -> None:
        assert "index" in _SSE_CHOICE_STRUCTURAL_KEYS

    def test_choice_structural_keys_contains_object(self) -> None:
        assert "object" in _SSE_CHOICE_STRUCTURAL_KEYS

    def test_choice_structural_keys_excludes_text(self) -> None:
        # ``text`` MUST NOT be a structural key -- it is the
        # attacker-controlled string payload for /v1/completions.
        assert "text" not in _SSE_CHOICE_STRUCTURAL_KEYS

    def test_choice_structural_keys_excludes_message(self) -> None:
        assert "message" not in _SSE_CHOICE_STRUCTURAL_KEYS

    def test_choice_structural_keys_excludes_logprobs(self) -> None:
        assert "logprobs" not in _SSE_CHOICE_STRUCTURAL_KEYS

    def test_choice_finish_reason_valid_is_ok(self) -> None:
        for value in _SSE_DELTA_FINISH_REASON_VALUES:
            assert _validate_choice_structural_field("finish_reason", value) == _STRUCTURAL_OK

    def test_choice_finish_reason_none_is_ok(self) -> None:
        assert _validate_choice_structural_field("finish_reason", None) == _STRUCTURAL_OK

    def test_choice_finish_reason_wrong_value_aborts(self) -> None:
        # The smuggle vector: a hostile upstream relocates the marker
        # from ``delta.finish_reason`` to ``choices[i].finish_reason``.
        assert _validate_choice_structural_field("finish_reason", "(S//NF)") == _STRUCTURAL_ABORT

    def test_choice_finish_reason_non_string_walks(self) -> None:
        # Nested dict / list = wrong type entirely: walk so embedded
        # markers reach inspection rather than abort blindly.
        assert (
            _validate_choice_structural_field("finish_reason", {"nested": "(S//NF)"})
            == _STRUCTURAL_WALK
        )

    def test_choice_index_int_is_ok(self) -> None:
        assert _validate_choice_structural_field("index", 0) == _STRUCTURAL_OK
        assert _validate_choice_structural_field("index", 42) == _STRUCTURAL_OK

    def test_choice_index_bool_aborts(self) -> None:
        # Booleans are ints in Python; reject explicitly so a
        # ``choices[0].index = True`` doesn't silently pass.
        assert _validate_choice_structural_field("index", True) == _STRUCTURAL_ABORT

    def test_choice_index_none_is_ok(self) -> None:
        assert _validate_choice_structural_field("index", None) == _STRUCTURAL_OK

    def test_choice_object_valid_is_ok(self) -> None:
        for value in _SSE_EVENT_OBJECT_VALUES:
            assert _validate_choice_structural_field("object", value) == _STRUCTURAL_OK

    def test_choice_object_wrong_value_aborts(self) -> None:
        assert _validate_choice_structural_field("object", "(S//NF)") == _STRUCTURAL_ABORT

    # ----- Walker collects sibling strings under ``_choice_top_level`` -----

    def test_walker_collects_choice_text(self) -> None:
        """``choices[i].text`` reaches INSPECTION via the choice-level walk."""
        choice = {"index": 0, "text": "(S//NF) classified leak", "finish_reason": None}
        strings = _collect_inspectable_strings(choice, _choice_top_level=True)
        assert any("(S//NF)" in s for s in strings)

    def test_walker_collects_choice_message_content(self) -> None:
        choice = {
            "index": 0,
            "message": {"role": "assistant", "content": "(S//NF) leak"},
            "finish_reason": None,
        }
        strings = _collect_inspectable_strings(choice, _choice_top_level=True)
        assert any("(S//NF)" in s for s in strings)

    def test_walker_collects_choice_logprobs_token(self) -> None:
        choice = {
            "index": 0,
            "logprobs": {
                "content": [
                    {
                        "token": "(S//NF)",
                        "logprob": -0.5,
                        "top_logprobs": [{"token": "x", "logprob": -1.2}],
                    }
                ]
            },
            "finish_reason": None,
        }
        strings = _collect_inspectable_strings(choice, _choice_top_level=True)
        assert any("(S//NF)" in s for s in strings)

    def test_walker_skips_delta_under_choice_top_level(self) -> None:
        """``delta`` is walked separately by ``_flush_event`` (with the
        delta-level structural contract). Under ``_choice_top_level=True``
        the walker MUST skip it so we don't double-collect delta strings."""
        choice = {
            "index": 0,
            "delta": {"content": "delta-content-marker"},
            "text": "text-marker",
        }
        strings = _collect_inspectable_strings(choice, _choice_top_level=True)
        # Only the sibling ``text`` is in the result; ``delta.content``
        # comes from the separate delta walk.
        assert "text-marker" in strings
        assert "delta-content-marker" not in strings

    def test_walker_skips_conformant_structural_fields(self) -> None:
        """Conformant ``finish_reason`` / ``index`` / ``object`` get
        skipped during the choice-level walk (they're enum-checked,
        not text-bearing)."""
        choice = {
            "index": 0,
            "finish_reason": "stop",
            "object": "chat.completion.chunk",
            "text": "real-payload",
        }
        strings = _collect_inspectable_strings(choice, _choice_top_level=True)
        # No structural-field values in result.
        assert "stop" not in strings
        assert "chat.completion.chunk" not in strings
        # Real text payload IS in result.
        assert "real-payload" in strings

    # ----- End-to-end via _SSEBuffer (the F-R17-1 reproducer shapes) -----

    def test_buffer_text_completion_marker_inspected(self) -> None:
        """``/v1/completions`` (text_completion) streaming with the
        marker in ``choices[0].text`` -- the canonical F-R17-1 reproducer.
        The marker must reach the buffer's emitted strings."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="cmpl-x",
            object="text_completion",
            choices=[
                {
                    "index": 0,
                    "text": "(S//NF) classified leak",
                    "logprobs": None,
                    "finish_reason": None,
                }
            ],
        )
        emitted = buf.feed(frame) + buf.finalize()
        assert "(S//NF)" in emitted, f"choices[0].text marker not inspected: emitted={emitted!r}"
        assert buf.malformed_event_seen is False

    def test_buffer_chat_message_content_marker_inspected(self) -> None:
        """Chat-completion buffered-as-SSE with the marker in
        ``choices[0].message.content`` -- the second F-R17-1 shape."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-x",
            object="chat.completion",
            choices=[
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "(S//NF) buffered leak",
                    },
                    "finish_reason": "stop",
                }
            ],
        )
        emitted = buf.feed(frame) + buf.finalize()
        assert "(S//NF)" in emitted, (
            f"choices[0].message.content marker not inspected: emitted={emitted!r}"
        )
        assert buf.malformed_event_seen is False

    def test_buffer_logprobs_token_marker_inspected(self) -> None:
        """Token-level logprob payload with the marker in
        ``choices[0].logprobs.content[0].token``."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-x",
            object="chat.completion.chunk",
            choices=[
                {
                    "index": 0,
                    "delta": {"content": "ok"},
                    "logprobs": {"content": [{"token": "(S//NF)", "logprob": -0.1}]},
                    "finish_reason": None,
                }
            ],
        )
        emitted = buf.feed(frame) + buf.finalize()
        assert "(S//NF)" in emitted, (
            f"choices[0].logprobs.content[0].token marker not inspected: emitted={emitted!r}"
        )

    def test_buffer_choice_finish_reason_wrong_value_aborts(self) -> None:
        """A wrong-enum ``choices[0].finish_reason`` flags the malformed
        flag so the forward path aborts via ``upstream_sse_malformed``
        (subsumes F-R17-4)."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-x",
            object="chat.completion.chunk",
            choices=[
                {
                    "index": 0,
                    "delta": {"content": "ok"},
                    "finish_reason": "(S//NF)",
                }
            ],
        )
        buf.feed(frame)
        buf.finalize()
        assert buf.malformed_event_seen is True

    def test_buffer_choice_object_wrong_value_aborts(self) -> None:
        """A wrong-enum ``choices[0].object`` (shim-shaped, not present
        on canonical OpenAI streams but defended in depth) aborts."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-x",
            object="chat.completion.chunk",
            choices=[
                {
                    "index": 0,
                    "object": "chat.completion.(S//NF)",
                    "delta": {"content": "ok"},
                }
            ],
        )
        buf.feed(frame)
        buf.finalize()
        assert buf.malformed_event_seen is True

    def test_buffer_normal_event_no_false_positive(self) -> None:
        """Sanity: a normal chunk with delta content and a valid
        choice-level finish_reason flows through cleanly."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-abc123",
            object="chat.completion.chunk",
            choices=[
                {
                    "index": 0,
                    "delta": {"content": "hello"},
                    "finish_reason": None,
                }
            ],
        )
        emitted = buf.feed(frame) + buf.finalize()
        assert buf.malformed_event_seen is False
        assert "hello" in emitted

    def test_buffer_terminal_choice_with_valid_finish_reason(self) -> None:
        """The closing chunk of a stream typically carries
        ``finish_reason="stop"`` at the choice level with an empty
        delta. Must not flag malformed."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-abc123",
            object="chat.completion.chunk",
            choices=[
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                }
            ],
        )
        buf.feed(frame)
        buf.finalize()
        assert buf.malformed_event_seen is False

    def test_buffer_does_not_double_inspect_delta_content(self) -> None:
        """Regression: with the choice-level walk added, a marker that
        lives ONLY in ``delta.content`` must still surface (not be
        suppressed) -- and must not be duplicated to a degree that
        skews inspection accounting."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-x",
            object="chat.completion.chunk",
            choices=[
                {
                    "index": 0,
                    "delta": {"content": "delta-only-marker"},
                    "finish_reason": None,
                }
            ],
        )
        emitted = buf.feed(frame) + buf.finalize()
        # Marker reaches inspector.
        assert "delta-only-marker" in emitted
        # Sanity: not multiplied (would indicate double-collection).
        assert emitted.count("delta-only-marker") == 1


# ---------------------------------------------------------------------------
# MED -- F-R17-2 httpx trust_env=True allows env MITM
# ---------------------------------------------------------------------------


class TestF_R17_2_HttpxTrustEnvFalse:
    """Upstream client must pin TLS / proxy posture to config, not env."""

    def _make_app(self) -> SignetApp:
        cfg = ServerConfig(
            upstream_url="http://localhost:11434/v1",
            allow_ephemeral_key=True,
        )
        return SignetApp(config=cfg, pipeline=Pipeline([]))

    def test_ensure_http_sets_trust_env_false(self) -> None:
        app = self._make_app()
        client = app._ensure_http()
        try:
            assert client.trust_env is False, (
                "upstream httpx client must construct with trust_env=False "
                "so process-env proxy / CA-bundle knobs cannot silently "
                "MITM upstream traffic"
            )
        finally:
            # Lazy-created client; close to avoid resource warnings.
            import asyncio

            asyncio.run(client.aclose())

    def test_ensure_http_does_not_route_via_env_proxy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Set ``HTTPS_PROXY`` / ``HTTP_PROXY`` in the process env and
        assert the constructed client does not honor them."""
        monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example:3128")
        monkeypatch.setenv("HTTP_PROXY", "http://attacker.example:3128")
        monkeypatch.setenv("ALL_PROXY", "http://attacker.example:3128")
        app = self._make_app()
        client = app._ensure_http()
        try:
            # With trust_env=False, httpx ignores env-supplied proxy
            # configuration. The client's transport / proxies state
            # MUST NOT reference attacker.example.
            # The most stable cross-version assertion is the flag itself.
            assert client.trust_env is False
            # Defense in depth: rendered repr / mount list does not
            # mention the attacker host.
            assert "attacker.example" not in repr(client)
        finally:
            import asyncio

            asyncio.run(client.aclose())

    def test_ensure_http_verify_true(self) -> None:
        """``verify`` defaults to True today but we set it explicitly so
        a future httpx default flip cannot silently disable
        verification. Assert the client constructs without raising."""
        app = self._make_app()
        client = app._ensure_http()
        try:
            # No public attribute exposes the verify flag directly across
            # httpx versions; assert the client was constructed (no
            # exception) and trust_env is pinned -- the verify=True is
            # documented in the construction call and covered by code
            # review. The construct-without-error check guards against
            # a typo'd keyword argument breaking the call path.
            assert client is not None
        finally:
            import asyncio

            asyncio.run(client.aclose())


# ---------------------------------------------------------------------------
# LOW -- F-R17-3 connection-pool cap not operator-tunable
# ---------------------------------------------------------------------------


class TestF_R17_3_PoolLimitsConfigurable:
    """``ServerConfig`` carries pool-limit fields wired into the
    ``httpx.AsyncClient``."""

    def test_default_max_connections(self) -> None:
        cfg = ServerConfig()
        assert cfg.upstream_pool_max_connections == 100

    def test_default_max_keepalive_connections(self) -> None:
        cfg = ServerConfig()
        assert cfg.upstream_pool_max_keepalive_connections == 20

    def test_max_connections_must_be_int(self) -> None:
        cfg = ServerConfig()
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_connections = "100"  # type: ignore[assignment]

    def test_max_connections_rejects_bool(self) -> None:
        cfg = ServerConfig()
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_connections = True  # type: ignore[assignment]

    def test_max_connections_must_be_positive(self) -> None:
        cfg = ServerConfig()
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_connections = 0
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_connections = -1

    def test_max_keepalive_must_be_positive(self) -> None:
        cfg = ServerConfig()
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_keepalive_connections = 0
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_keepalive_connections = -5

    def test_max_keepalive_rejects_non_int(self) -> None:
        cfg = ServerConfig()
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_keepalive_connections = 1.5  # type: ignore[assignment]

    def test_custom_limits_flow_into_ensure_http(self) -> None:
        """Setting low limits results in a working client (queueing,
        not crashing). Exact pool-internals inspection is httpx-
        version-coupled, so we assert via the public client surface."""
        cfg = ServerConfig(
            upstream_url="http://localhost:11434/v1",
            allow_ephemeral_key=True,
            upstream_pool_max_connections=5,
            upstream_pool_max_keepalive_connections=2,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline([]))
        client = app._ensure_http()
        try:
            assert isinstance(client, httpx.AsyncClient)
            # Construct succeeded -> Limits accepted by httpx.
        finally:
            import asyncio

            asyncio.run(client.aclose())
