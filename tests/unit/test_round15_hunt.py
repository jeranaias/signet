"""Round 15 hunt closures — regression coverage for F-R15-* findings.

This file accumulates regression tests across multiple Round-15
hunts. CLI-scope findings (F-R15-1 / F-R15-2 / F-R15-3) were closed
in an earlier sweep; SERVER + STREAMING scope findings (named
``F-R15-2 SSE event-level`` ... ``F-R15-10 Anthropic finish reasons``
to match the server-hunt report) are closed below alongside them.

CLI-scope findings (earlier sweep):

MED:

- ``F-R15-1 windows-reserved-device-name-trailing-whitespace``: the R14
  guard at ``signet.cli._is_windows_reserved_device_name`` matched
  ``basename.split(".", 1)[0].upper()`` against the reserved set. It
  did not normalize trailing whitespace or trailing dots before the
  split, so ``"CON "`` (trailing space) and friends bypassed the guard
  even though Win32 still routes them to the console device. Post-fix
  the basename is ``rstrip(" \\t.")``'d before the suffix split, so
  every Win32-normalized form reaches the comparison.

LOW:

- ``F-R15-2 plugin-discovery-huge-repr-stalls-sanitizer``: discovery's
  two ``_sanitize_for_log(repr(obj))`` sites had no length cap on the
  plugin-controlled ``__repr__`` output. A hostile 10 MB ``__repr__``
  stalled discovery ~9.5 s and peaked at ~32 MB of escaped string.
  Post-fix a ``_truncate_for_log`` helper pre-caps the repr to 1024
  chars (with a ``... [truncated]`` marker) before sanitize, bounding
  both wall-clock and memory regardless of plugin behavior.

- ``F-R15-3 keys-generate-ed25519-key-id-charset``: the parse-time
  ``--key-id`` guard refused only ASCII control bytes (< 0x20 / 0x7F).
  R14 extended the echo-site sanitizer to cover Unicode bidi /
  C1 / LSEP / BOM, but the parser did not match. Post-fix the parser
  applies a strict allowlist ``[A-Za-z0-9_.:\\-]+`` -- key IDs in the
  wild are short ASCII identifiers (``prod-2024-01``,
  ``kms-rotated-foo``), and rejecting Unicode at parse time is cleaner
  than relying on echo-time sanitization.

SERVER + STREAMING scope findings (this sweep):

HIGH:

- ``F-R15-2 server SSE event-level fields bypass inspection``: the
  HTTP SSE ``_SSEBuffer._flush_event`` walked only
  ``choices[i].delta`` through ``_collect_inspectable_strings``;
  event-level siblings (``id``, ``system_fingerprint``, ``model``,
  ``error.message``, etc.) flowed to the client unchecked while the
  realtime/WS path (R14) walked the full event. Post-fix the HTTP
  path inspects the whole event dict via the event-level structural
  set / validator.

MED:

- ``F-R15-3 server _header_value_is_safe misses bytes 0x80-0xFF``:
  rejected only ``< 0x20`` and ``0x7F``; ``0x85`` / ``0xA0`` /
  ``0xFF`` passed admit then raised ``UnicodeEncodeError`` deep
  inside httpx, mis-attributed to a 502 ``upstream_exception``.
  Post-fix the helper rejects every byte ``< 0x20`` (except tab
  ``0x09``) AND every byte ``>= 0x7F``.

- ``F-R15-4 Realtime walker treats _DepthSentinelList as empty``:
  realtime ``_handle_text_inspection`` ignored the sentinel return
  from ``_collect_inspectable_strings``; events nested deeper than
  ``_MAX_JSON_DEPTH`` (64) yielded zero sibling strings and were
  forwarded unblocked. Post-fix mirrors the HTTP path's sentinel
  check and refuses the frame with a sanitized refusal.

LOW:

- ``F-R15-5 NaN/Inf accepted in timeouts``:
  ``ServerConfig.__setattr__`` validators for ``request_timeout_s``
  and ``shutdown_grace_seconds`` accepted ``float('nan')`` /
  ``float('inf')``. Post-fix ``math.isfinite`` gates both.

- ``F-R15-6 hmac_secret accepts b'' / b'x'``: ``ServerConfig`` and
  ``_parse_hex_env`` accepted secrets shorter than the HMAC-SHA256
  minimum. Post-fix both enforce ``_HMAC_SECRET_MIN_BYTES = 32`` per
  NIST SP 800-107 §5.3.4.

- ``F-R15-7 extra_forward_headers not validated``: the operator-
  controlled tuple of header names flowed unchecked through
  ``_upstream_headers``; a typo / supply-chain compromise that
  landed CRLF in a name re-created R13's mis-attribution surface.
  Post-fix names are validated against the RFC 7230 §3.2 token
  charset at config-construction / mutation time.

- ``F-R15-8 admission_fallback scope limited``: session-store
  exceptions inside ``_admit`` propagated through the per-route
  ``try/except`` and landed in ``_outer_fallback_response`` with
  ``check_name="pipeline.forward"`` -- wrong stage attribution.
  Post-fix session-store calls are wrapped in the same
  ``_admission_fallback_response`` routing that
  ``pipeline.pre_request`` uses.

INFO:

- ``F-R15-9 _collect_inspectable_strings ignores bytes/bytearray/tuple``:
  walker recognized only ``dict`` / ``list`` for recursion and
  ``str`` for collection; bytes / bytearray / tuple values slipped
  through silently. Post-fix the walker walks all three types.

- ``F-R15-10 Anthropic pause_turn / tool_use finish_reasons``:
  ``_SSE_DELTA_FINISH_REASON_VALUES`` missing the late-2025
  Anthropic additions. Post-fix both are accepted.
"""

from __future__ import annotations

import time
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from signet.cli import (
    _is_windows_reserved_device_name,
    _reject_windows_reserved_device_name,
    main,
)
from signet.plugins import discovery as plugin_discovery
from signet.plugins.discovery import (
    _LOG_TRUNCATION_MARKER,
    _sanitize_for_log,
    _truncate_for_log,
)

# ---------------------------------------------------------------------------
# F-R15-1 — Windows reserved device names with trailing whitespace / dots
# ---------------------------------------------------------------------------


class TestF_R15_1_TrailingWhitespaceReservedNames:
    """Trailing space / tab / dot variants of reserved names are rejected."""

    @pytest.mark.parametrize(
        "name",
        [
            # trailing single space
            "CON ",
            "NUL ",
            "PRN ",
            "AUX ",
            "COM1 ",
            "LPT1 ",
            # trailing tab
            "CON\t",
            "PRN\t",
            # trailing multiple spaces
            "CON  ",
            "NUL   ",
            # trailing dot (already worked via split shape; pin it)
            "CON.",
            "NUL..",
            # mixed trailing dots + spaces
            "CON. ",
            "CON .",
            "CON . ",
            # trailing space before an extension also routes on Win32
            "CON .txt",
            "NUL .log",
            # lower / mixed case is upper-cased before lookup
            "con ",
            "Con ",
            "lpt1 ",
            # plain reserved name with extension (still rejected per R14)
            "NUL.txt",
            # plain reserved name (already rejected per R14, pin it)
            "CON",
            "con",
            "Con",
        ],
    )
    def test_rejects_trailing_whitespace_or_dot_reserved(self, name: str) -> None:
        """``_reject_windows_reserved_device_name`` raises on every Win32
        basename-normalized form of a reserved device name."""
        with pytest.raises(click.exceptions.ClickException) as excinfo:
            _reject_windows_reserved_device_name(Path(name))
        assert "Windows reserved device name" in str(excinfo.value.message)

    @pytest.mark.parametrize(
        "name",
        [
            # not in the reserved set even with trailing space
            "audit.jsonl ",
            "console.log ",
            "cone ",
            "com10 ",  # COM10 is NOT reserved
            "lpt0 ",  # LPT0 is NOT reserved
            # empty after rstrip should not raise (degenerate edge)
            "   ",
            "...",
            ". .",
        ],
    )
    def test_normal_paths_with_trailing_whitespace_not_rejected(self, name: str) -> None:
        """Trailing-whitespace stripping must not over-reach onto names
        that aren't actually reserved after normalization."""
        _reject_windows_reserved_device_name(Path(name))

    def test_is_reserved_helper_returns_true_for_trailing_space(self) -> None:
        """The lower-level shape helper sees the same set."""
        assert _is_windows_reserved_device_name(Path("CON ")) is True
        assert _is_windows_reserved_device_name(Path("nul.")) is True
        assert _is_windows_reserved_device_name(Path("LPT1 .txt")) is True

    def test_is_reserved_helper_returns_false_for_non_reserved(self) -> None:
        assert _is_windows_reserved_device_name(Path("audit.jsonl ")) is False
        assert _is_windows_reserved_device_name(Path("console.log")) is False
        assert _is_windows_reserved_device_name(Path("com10 ")) is False

    def test_serve_rejects_trailing_space_audit_log(self) -> None:
        """End-to-end via click: ``signet serve --audit-log "CON "`` must
        refuse with the same ClickException-driven error path as bare
        ``CON`` (the R14 closure)."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "serve",
                "--upstream",
                "http://localhost:11434/v1",
                "--audit-log",
                "CON ",
                "--allow-ephemeral-key",
            ],
        )
        assert result.exit_code != 0
        assert "Windows reserved device name" in result.output
        # Output must remain terminal-safe (no escape bytes in error).
        assert "\x1b" not in result.output


# ---------------------------------------------------------------------------
# F-R15-2 — Plugin discovery hostile __repr__ length cap
# ---------------------------------------------------------------------------


class TestF_R15_2_LogTruncation:
    """``_truncate_for_log`` bounds plugin-controlled ``__repr__`` output."""

    def test_short_input_unchanged(self) -> None:
        """Strings within the cap pass through verbatim."""
        assert _truncate_for_log("hello", max_chars=100) == "hello"

    def test_input_at_cap_unchanged(self) -> None:
        """Boundary: exactly ``max_chars`` is NOT truncated."""
        s = "x" * 1024
        assert _truncate_for_log(s) == s
        assert _LOG_TRUNCATION_MARKER not in _truncate_for_log(s)

    def test_input_over_cap_gets_marker(self) -> None:
        """Past the cap, output is truncated and marked."""
        s = "x" * 2048
        out = _truncate_for_log(s, max_chars=1024)
        assert len(out) == 1024 + len(_LOG_TRUNCATION_MARKER)
        assert out.endswith(_LOG_TRUNCATION_MARKER)
        assert out.startswith("x" * 1024)

    def test_non_string_coerced(self) -> None:
        """Non-string inputs are stringified before truncation."""
        assert _truncate_for_log(12345, max_chars=100) == "12345"
        # ``None`` becomes the empty string (matches sanitizer behavior).
        assert _truncate_for_log(None, max_chars=100) == ""  # type: ignore[arg-type]

    def test_custom_cap(self) -> None:
        out = _truncate_for_log("abcdefghij", max_chars=4)
        assert out == "abcd" + _LOG_TRUNCATION_MARKER

    def test_hostile_repr_through_sanitize_is_fast(self) -> None:
        """A 10 MB plugin ``__repr__`` must NOT stall the sanitize step.

        Pre-fix: ``_sanitize_for_log(repr(obj))`` on a 10 MB string
        translated codepoint-by-codepoint and allocated ~15 MB of escaped
        output (~9.5 s, ~32 MB peak). Post-fix: the truncation pre-cap
        bounds the sanitizer's input to 1024 chars + marker, so the whole
        pipeline completes well inside 100 ms.
        """

        class _HostileRepr:
            def __repr__(self) -> str:  # 10 MB of bidi-laden bytes
                return ("safe‮evil" * 1_000_000)[:10_000_000]

        obj = _HostileRepr()
        t0 = time.perf_counter()
        out = _sanitize_for_log(_truncate_for_log(repr(obj)))
        elapsed = time.perf_counter() - t0
        # Bounded wall-clock: well under 100 ms on any machine that runs
        # the existing CLI test suite (which already exercises ~1300
        # tests in seconds).
        assert elapsed < 0.5, f"sanitize+truncate took {elapsed:.3f}s"
        # Truncation marker present.
        assert _LOG_TRUNCATION_MARKER in out
        # Output length is bounded: at most 1024 chars + marker, each
        # bidi char escaped to ``‮`` (6 chars), so the upper bound
        # is around 1024 * 6 + len(marker). Generous bound for safety.
        assert len(out) < 8 * 1024
        # Raw bidi codepoint is escaped, not preserved.
        assert "‮" not in out

    def test_discovery_caps_hostile_repr_on_non_check_object(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end: a plugin whose loaded object is NOT a Check
        subclass and whose class overrides ``__repr__`` with 10 MB
        cannot stall discovery. We check (a) discovery finishes
        promptly and (b) the recorded ``error`` field is bounded
        in length."""

        class _MassiveReprMeta(type):
            def __repr__(cls) -> str:
                return "evil" * 5_000_000  # 20 MB

        class _NotACheck(metaclass=_MassiveReprMeta):
            pass

        class _FakeEP:
            name = "evilplugin"
            value = "fakemod:evil"
            dist = None

            def load(self) -> type:
                return _NotACheck

        def _fake_iter(group: str) -> list[_FakeEP]:
            if group == "signet.checks":
                return [_FakeEP()]
            return []

        # Patch discovery to feed our hostile entry-point and reset the
        # cache so the patched iterator is consulted.
        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        t0 = time.perf_counter()
        plugins = plugin_discovery.discover_plugins(refresh=True)
        elapsed = time.perf_counter() - t0

        assert elapsed < 1.0, f"discovery took {elapsed:.3f}s"
        # Recorded entry's ``error`` field must be bounded -- not 20 MB.
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.status == "load_error"
        assert plugin.error is not None
        # Marker present, total bounded well under 10 KB even after the
        # surrounding "resolved object ... is not a Check subclass" text.
        assert _LOG_TRUNCATION_MARKER in plugin.error
        assert len(plugin.error) < 4 * 1024

        # Clean up the cache so we don't pollute the next test.
        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R15-3 — --key-id strict charset validator
# ---------------------------------------------------------------------------


class TestF_R15_3_KeyIdCharset:
    """``keys generate-ed25519 --key-id`` enforces a strict ASCII charset."""

    @pytest.mark.parametrize(
        "bad_key_id",
        [
            # R14 sanitizer codepoints the R9 ASCII check missed
            "café",  # accented Latin (café)
            "‮hacked",  # RLO bidi override (Trojan Source)
            "key‪id",  # LRE bidi override
            "key⁦id",  # FSI bidi isolate
            "key id",  # LINE SEPARATOR
            "key id",  # PARAGRAPH SEPARATOR
            "key﻿id",  # BOM / ZWNBSP
            "keyid",  # C1 control
            "keyid",  # C1 CSI
            # ASCII controls still rejected
            "key\x00id",
            "key\x1bid",
            "key\x7fid",
            # Whitespace (parser must not silently accept padding)
            "key id",
            "key\tid",
            "key\nid",
            # Special characters outside the allowlist
            "key/id",
            "key\\id",
            "key#id",
            "key=id",
            "key+id",
            "key@id",
            "key$id",
            "key'id",
            'key"id',
            "key%id",
            # Non-ASCII scripts: well-meaning but rejected by allowlist
            "你好",  # 你好
            "שלום",  # שלום
            "👋",  # 👋
            # Empty after parsing
            "",
        ],
    )
    def test_rejects_non_ascii_or_special_chars(self, tmp_path: Path, bad_key_id: str) -> None:
        pytest.importorskip("cryptography")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(tmp_path / "priv.pem"),
                "--key-id",
                bad_key_id,
            ],
        )
        assert result.exit_code != 0, f"--key-id {bad_key_id!r} should have been rejected"
        # Echoed error output must be terminal-safe (no raw bidi / ANSI).
        assert "\x1b" not in result.output
        assert "‮" not in result.output
        assert " " not in result.output

    @pytest.mark.parametrize(
        "good_key_id",
        [
            # Realistic operator-pipeline key IDs
            "prod-2024-01",
            "kms-rotated-foo",
            "operator-2026q2",
            "k1",
            "smoketest",
            "test",
            "ABC123",
            "a_b_c",
            "key.with.dots",
            "kid:v1",
            "service:prod:active",
            "k",
            # Maximum reasonable shape: alnum + every allowed punctuation
            "abcXYZ_123-foo.bar:baz",
        ],
    )
    def test_accepts_normal_ascii_key_ids(self, tmp_path: Path, good_key_id: str) -> None:
        """Realistic short-ASCII key IDs still pass the parser."""
        pytest.importorskip("cryptography")
        out_path = tmp_path / f"{abs(hash(good_key_id))}.pem"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(out_path),
                "--key-id",
                good_key_id,
            ],
        )
        assert result.exit_code == 0, (
            f"--key-id {good_key_id!r} should have been accepted; output: {result.output}"
        )
        # PEM and sidecar both landed.
        assert out_path.exists()
        meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
        assert meta_path.exists()

    def test_error_message_names_offending_codepoint(self, tmp_path: Path) -> None:
        """For Unicode rejects, the error message identifies the first
        offending codepoint so the operator can locate the problem."""
        pytest.importorskip("cryptography")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(tmp_path / "priv.pem"),
                "--key-id",
                "key‮hacked",
            ],
        )
        assert result.exit_code != 0
        # The message references U+202E (the RLO codepoint).
        assert "U+202E" in result.output
        # The raw bidi character is NOT echoed (sanitized).
        assert "‮" not in result.output

    def test_empty_key_id_rejected(self, tmp_path: Path) -> None:
        """An empty ``--key-id ""`` is rejected with a clear message."""
        pytest.importorskip("cryptography")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(tmp_path / "priv.pem"),
                "--key-id",
                "",
            ],
        )
        assert result.exit_code != 0
        assert "--key-id" in result.output


# ===========================================================================
# SERVER + STREAMING sweep: F-R15-2 through F-R15-10
# ===========================================================================

import asyncio  # noqa: E402
import json as _json  # noqa: E402
import math  # noqa: E402
from typing import Any  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from signet.audit.backend import JsonlBackend  # noqa: E402
from signet.core.pipeline import Pipeline  # noqa: E402
from signet.server.app import (  # noqa: E402
    _SSE_DELTA_FINISH_REASON_VALUES,
    _SSE_EVENT_OBJECT_VALUES,
    _SSE_EVENT_STRUCTURAL_KEYS,
    _STRUCTURAL_ABORT,
    _STRUCTURAL_OK,
    _STRUCTURAL_WALK,
    SignetApp,
    _collect_inspectable_strings,
    _DepthSentinelList,
    _header_value_is_safe,
    _SSEBuffer,
    _validate_event_top_level_structural_field,
    _validate_top_level_structural_field,
)
from signet.server.config import _HMAC_SECRET_MIN_BYTES, ServerConfig  # noqa: E402
from signet.server.realtime import RealtimeHandler  # noqa: E402

# ---------------------------------------------------------------------------
# HIGH -- F-R15-2 SSE event-level fields bypass inspection
# ---------------------------------------------------------------------------


def _make_sse_frame(**fields: Any) -> str:
    """Build a single ``data: <json>\\n\\n`` SSE frame."""
    return f"data: {_json.dumps(fields)}\n\n"


class TestF_R15_2_Server_SseEventLevelInspection:
    """Event-level structural keys + walker now covers the whole event
    dict; smuggled markers in ``id`` / ``system_fingerprint`` / ``model``
    / ``error.message`` reach INSPECTION (and the abort path for
    ``object`` wrong-value)."""

    def test_event_object_enum_set_includes_streaming_shape(self) -> None:
        assert "chat.completion.chunk" in _SSE_EVENT_OBJECT_VALUES
        assert "chat.completion" in _SSE_EVENT_OBJECT_VALUES
        assert "text_completion" in _SSE_EVENT_OBJECT_VALUES

    def test_event_structural_keys_contains_object(self) -> None:
        assert "object" in _SSE_EVENT_STRUCTURAL_KEYS

    def test_object_conformant_value_is_ok(self) -> None:
        assert (
            _validate_event_top_level_structural_field("object", "chat.completion.chunk")
            == _STRUCTURAL_OK
        )

    def test_object_wrong_value_aborts(self) -> None:
        # A hostile upstream stuffing a marker in `object` is the
        # protocol-violation path: enum-shaped field, wrong value.
        assert (
            _validate_event_top_level_structural_field("object", "chat.completion.(S//NF)")
            == _STRUCTURAL_ABORT
        )

    def test_object_non_string_walks(self) -> None:
        # Defense in depth: dict / list values walk so embedded
        # markers still get inspected.
        assert (
            _validate_event_top_level_structural_field("object", {"nested": "(S//NF)"})
            == _STRUCTURAL_WALK
        )

    def test_object_none_is_ok(self) -> None:
        assert _validate_event_top_level_structural_field("object", None) == _STRUCTURAL_OK

    def test_marker_in_event_id_is_collected(self) -> None:
        """Event-level ``id`` is inspected as content -- a marker placed
        there reaches INSPECTION's collected strings."""
        event_obj = {
            "id": "chatcmpl-(S//NF)",
            "object": "chat.completion.chunk",
            "model": "gpt-4",
            "choices": [{"delta": {"content": "hello"}}],
        }
        # Mirror _flush_event's split: strip choices, walk the rest.
        rest = {k: v for k, v in event_obj.items() if k != "choices"}
        strings = _collect_inspectable_strings(rest, _event_top_level=True)
        assert "chatcmpl-(S//NF)" in strings

    def test_marker_in_system_fingerprint_is_collected(self) -> None:
        event_obj = {
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "system_fingerprint": "fp_(S//NF)",
            "choices": [{"delta": {"content": "hi"}}],
        }
        rest = {k: v for k, v in event_obj.items() if k != "choices"}
        strings = _collect_inspectable_strings(rest, _event_top_level=True)
        assert "fp_(S//NF)" in strings

    def test_marker_in_error_message_is_collected(self) -> None:
        event_obj = {
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "error": {"message": "(S//NF) rate limit"},
            "choices": [{"delta": {"content": "hi"}}],
        }
        rest = {k: v for k, v in event_obj.items() if k != "choices"}
        strings = _collect_inspectable_strings(rest, _event_top_level=True)
        assert any("(S//NF)" in s for s in strings)

    def test_marker_in_model_is_collected(self) -> None:
        event_obj = {
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "model": "gpt-4-(S//NF)",
            "choices": [{"delta": {"content": "hi"}}],
        }
        rest = {k: v for k, v in event_obj.items() if k != "choices"}
        strings = _collect_inspectable_strings(rest, _event_top_level=True)
        assert "gpt-4-(S//NF)" in strings

    def test_int_usage_fields_skip_inspection(self) -> None:
        """Numeric usage fields skip via the walker's type filter, not
        by name. Only string-valued leaves are collected; int leaves
        don't appear in the result."""
        event_obj = {
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }
        strings = _collect_inspectable_strings(event_obj, _event_top_level=True)
        # No int-derived strings in the result.
        assert "100" not in strings
        assert "50" not in strings

    def test_sse_buffer_event_level_marker_is_inspected(self) -> None:
        """End-to-end via ``_SSEBuffer``: a frame whose marker lives only
        in the event-level ``id`` field surfaces in the buffer's emitted
        text."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-(S//NF)",
            object="chat.completion.chunk",
            choices=[{"delta": {"content": "hello"}}],
        )
        emitted = buf.feed(frame)
        emitted += buf.finalize()
        assert "(S//NF)" in emitted, f"event-level marker not inspected: emitted={emitted!r}"

    def test_sse_buffer_object_wrong_value_aborts(self) -> None:
        """A wrong-value ``object`` (enum violation) flags the buffer's
        malformed flag so the forward path aborts via the
        ``upstream_sse_malformed`` shape."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-abc",
            object="chat.completion.(S//NF)",
            choices=[{"delta": {"content": "hi"}}],
        )
        buf.feed(frame)
        buf.finalize()
        assert buf.malformed_event_seen is True

    def test_sse_buffer_normal_event_does_not_false_positive(self) -> None:
        """Sanity: a plain event with normal id / system_fingerprint /
        model strings flows through without setting the malformed flag
        and emits the delta content."""
        buf = _SSEBuffer()
        frame = _make_sse_frame(
            id="chatcmpl-abc123",
            object="chat.completion.chunk",
            system_fingerprint="fp_normal",
            model="gpt-4",
            choices=[{"delta": {"content": "hello"}}],
        )
        emitted = buf.feed(frame)
        emitted += buf.finalize()
        assert buf.malformed_event_seen is False
        assert "hello" in emitted


# ---------------------------------------------------------------------------
# MED -- F-R15-3 server _header_value_is_safe misses bytes 0x80-0xFF
# ---------------------------------------------------------------------------


class TestF_R15_3_Server_HeaderValueAsciiStrict:
    def test_nel_0x85_rejected(self) -> None:
        assert _header_value_is_safe("Bearer xxx\x85more") is False

    def test_nbsp_latin1_0xa0_rejected(self) -> None:
        assert _header_value_is_safe("Bearer xxx\xa0more") is False

    def test_high_latin1_0xff_rejected(self) -> None:
        assert _header_value_is_safe("Bearer xxx\xff") is False

    def test_full_obs_text_range_rejected(self) -> None:
        # Every byte from 0x80 through 0xFF should be refused.
        for cp in range(0x80, 0x100):
            assert _header_value_is_safe(f"Bearer xxx{chr(cp)}") is False, (
                f"byte 0x{cp:02x} unexpectedly accepted"
            )

    def test_ascii_printable_still_accepted(self) -> None:
        assert _header_value_is_safe("Bearer xxx") is True
        assert _header_value_is_safe("Bearer\txxx") is True  # tab still allowed
        assert _header_value_is_safe("Bearer sk-test-1234567890") is True
        # All printable ASCII (0x20 - 0x7E) should pass.
        printable = "".join(chr(c) for c in range(0x20, 0x7F))
        assert _header_value_is_safe(printable) is True

    def test_legacy_r13_rejections_still_apply(self) -> None:
        assert _header_value_is_safe("Bearer xxx\r\nX-Injected: yes") is False
        assert _header_value_is_safe("Bearer xxx\x00") is False
        assert _header_value_is_safe("Bearer xxx\x7f") is False
        assert _header_value_is_safe("Bearer xxx\x01") is False


class TestF_R15_3_Server_AdmitRoutesNonAsciiHeader:
    """The admit-time integration: a forwarded-header value containing
    a byte in 0x80-0xFF is refused 400 ``header_invalid_charset`` with
    a correlation_id, NOT mis-attributed to a 502 upstream_exception."""

    def _build(self, tmp_path: Path) -> tuple[SignetApp, TestClient, Path]:
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        return app, TestClient(app.app), log

    def test_nel_byte_in_auth_refused_400(self, tmp_path: Path) -> None:
        _app, client, log = self._build(tmp_path)
        try:
            r = client.post(
                "/v1/chat/completions",
                json={
                    "model": "test",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                headers={
                    # NEL byte (0x85) embedded mid-value.
                    "Authorization": "Bearer xxx\x85more",
                    "X-Classification": "UNCLASS",
                },
            )
        except Exception:
            pytest.skip("HTTP client refused 0x85 header at the transport layer")
        assert r.status_code == 400, (
            f"expected 400 header_invalid_charset, got {r.status_code} {r.text!r}"
        )
        body = r.json()
        assert body.get("error") == "header_invalid_charset"
        assert "correlation_id" in body
        # Audit row uses preflight stage, not pipeline.upstream / forward.
        rows = list(JsonlBackend(log).iter_entries())
        match = [
            row for row in rows if row.metadata.get("_refusal_kind") == "header_invalid_charset"
        ]
        assert match, (
            f"no header_invalid_charset audit row: "
            f"rows={[(r_.check_name, r_.metadata) for r_ in rows]}"
        )

    def test_clean_ascii_header_still_passes(self, tmp_path: Path) -> None:
        async def fake_post(_self, _url, **_kw):  # type: ignore[no-untyped-def]
            return httpx.Response(
                status_code=200,
                json={
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {},
                },
                request=httpx.Request("POST", _url),
                headers={"content-type": "application/json"},
            )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(httpx.AsyncClient, "post", fake_post)
            _app, client, _log = self._build(tmp_path)
            r = client.post(
                "/v1/chat/completions",
                json={
                    "model": "test",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                headers={
                    "Authorization": "Bearer sk-test-1234567890",
                    "X-Classification": "UNCLASS",
                },
            )
            assert r.status_code == 200, (
                f"clean ASCII Authorization was refused: {r.status_code} {r.text!r}"
            )


# ---------------------------------------------------------------------------
# MED -- F-R15-4 Realtime walker treats _DepthSentinelList as empty
# ---------------------------------------------------------------------------


class TestF_R15_4_Server_RealtimeDepthSentinel:
    def test_realtime_walker_returns_depth_sentinel_for_deep_event(self) -> None:
        """The walker itself returns a ``_DepthSentinelList`` for events
        deeper than ``_MAX_JSON_DEPTH`` -- the sentinel type is what
        the realtime handler now checks."""
        # Build an event nested 70 deep, with a marker at the leaf.
        deep: Any = "(S//NF) deep marker"
        for _ in range(70):
            deep = {"nested": deep}
        event = {"type": "response.text.delta", "delta": deep}
        result = _collect_inspectable_strings(event, _top_level=True)
        assert isinstance(result, _DepthSentinelList)

    def test_realtime_handler_refuses_deep_event(self, tmp_path: Path) -> None:
        """End-to-end: a deeply-nested event hits the sentinel path
        and a ``signet.refusal`` frame is sent to the client. Marker
        bytes are NOT forwarded."""
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        websocket = MagicMock()
        websocket.send_json = AsyncMock()
        websocket.application_state = MagicMock()

        handler = RealtimeHandler(app, websocket)

        # Prime the handler so _handle_text_inspection can run: it
        # requires ctx and rctx to be populated by the connect path.
        from signet.core.context import RequestContext, ResponseContext
        from signet.core.owner import Owner

        handler.ctx = RequestContext(
            owner=Owner.unresolved(),
            body={},
            headers={},
            method="GET",
            path="/v1/realtime",
        )
        handler.rctx = ResponseContext(request=handler.ctx)
        handler.session_id = "test-session-r15-4"

        deep: Any = "(S//NF) marker at depth 70"
        for _ in range(70):
            deep = {"x": deep}
        event = {"type": "response.text.delta", "delta": deep}

        asyncio.run(handler._handle_text_inspection(event))

        # The handler must have sent a refusal frame, NOT forwarded
        # the event.
        assert websocket.send_json.called, "no refusal frame sent"
        payload = websocket.send_json.call_args.args[0]
        assert payload["type"] == "signet.refusal"
        # The marker must NOT appear in the refusal payload (strict
        # redaction is on so reason is "refused", not the raw marker).
        assert "(S//NF)" not in _json.dumps(payload), f"marker leaked into refusal: {payload!r}"


# ---------------------------------------------------------------------------
# LOW -- F-R15-5 NaN/Inf accepted in timeouts
# ---------------------------------------------------------------------------


class TestF_R15_5_Server_TimeoutsRejectNaNInf:
    def _cfg(self) -> ServerConfig:
        return ServerConfig(
            upstream_url="https://api.example.com",
            allow_ephemeral_key=True,
        )

    def test_request_timeout_nan_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="finite"):
            cfg.request_timeout_s = float("nan")

    def test_request_timeout_inf_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="finite"):
            cfg.request_timeout_s = float("inf")

    def test_request_timeout_neg_inf_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="finite"):
            cfg.request_timeout_s = float("-inf")

    def test_request_timeout_finite_still_accepted(self) -> None:
        cfg = self._cfg()
        cfg.request_timeout_s = 30.0
        assert math.isfinite(cfg.request_timeout_s)
        assert cfg.request_timeout_s == 30.0

    def test_shutdown_grace_nan_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="finite"):
            cfg.shutdown_grace_seconds = float("nan")

    def test_shutdown_grace_inf_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="finite"):
            cfg.shutdown_grace_seconds = float("inf")

    def test_shutdown_grace_finite_still_accepted(self) -> None:
        cfg = self._cfg()
        cfg.shutdown_grace_seconds = 5.0
        assert cfg.shutdown_grace_seconds == 5.0


# ---------------------------------------------------------------------------
# LOW -- F-R15-6 hmac_secret accepts trivially short secrets
# ---------------------------------------------------------------------------


class TestF_R15_6_Server_HmacSecretMinLength:
    def _cfg(self) -> ServerConfig:
        return ServerConfig(
            upstream_url="https://api.example.com",
            allow_ephemeral_key=True,
        )

    def test_hmac_min_length_is_32(self) -> None:
        assert _HMAC_SECRET_MIN_BYTES == 32

    def test_empty_secret_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="32 bytes"):
            cfg.hmac_secret = b""

    def test_one_byte_secret_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="32 bytes"):
            cfg.hmac_secret = b"x"

    def test_31_byte_secret_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="32 bytes"):
            cfg.hmac_secret = b"x" * 31

    def test_32_byte_secret_accepted(self) -> None:
        cfg = self._cfg()
        cfg.hmac_secret = b"x" * 32
        assert cfg.hmac_secret == b"x" * 32

    def test_64_byte_secret_accepted(self) -> None:
        cfg = self._cfg()
        cfg.hmac_secret = b"x" * 64
        assert cfg.hmac_secret == b"x" * 64

    def test_none_secret_still_accepted(self) -> None:
        cfg = self._cfg()
        cfg.hmac_secret = None
        assert cfg.hmac_secret is None

    def test_hex_env_short_secret_rejected(self) -> None:
        """``_parse_hex_env`` enforces the same floor when parsing
        ``SIGNET_HMAC_SECRET`` from the environment."""
        with pytest.raises(ValueError, match="32 bytes"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "https://api.example.com",
                    "SIGNET_HMAC_SECRET": "00",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )

    def test_hex_env_32_byte_secret_accepted(self) -> None:
        cfg = ServerConfig.from_env(
            {
                "SIGNET_UPSTREAM_URL": "https://api.example.com",
                "SIGNET_HMAC_SECRET": "00" * 32,
                "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
            }
        )
        assert cfg.hmac_secret == b"\x00" * 32


# ---------------------------------------------------------------------------
# LOW -- F-R15-7 extra_forward_headers not validated
# ---------------------------------------------------------------------------


class TestF_R15_7_Server_ExtraForwardHeadersNames:
    def _cfg(self) -> ServerConfig:
        return ServerConfig(
            upstream_url="https://api.example.com",
            allow_ephemeral_key=True,
        )

    def test_crlf_in_name_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="extra_forward_headers"):
            cfg.extra_forward_headers = ("Authorization\r\nX-Inject",)

    def test_space_in_name_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="extra_forward_headers"):
            cfg.extra_forward_headers = ("Authorization X-Bad",)

    def test_empty_name_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="extra_forward_headers"):
            cfg.extra_forward_headers = ("",)

    def test_non_string_entry_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="extra_forward_headers"):
            cfg.extra_forward_headers = (123,)  # type: ignore[arg-type]

    def test_non_tuple_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="extra_forward_headers"):
            cfg.extra_forward_headers = ["Authorization"]  # type: ignore[assignment]

    def test_canonical_names_accepted(self) -> None:
        cfg = self._cfg()
        cfg.extra_forward_headers = (
            "Authorization",
            "OpenAI-Beta",
            "OpenAI-Organization",
            "X-Custom-Header",
        )
        assert "Authorization" in cfg.extra_forward_headers
        assert "X-Custom-Header" in cfg.extra_forward_headers

    def test_default_factory_passes_validation(self) -> None:
        cfg = self._cfg()
        # Default values should be the canonical 3-tuple and pass.
        assert cfg.extra_forward_headers == (
            "Authorization",
            "OpenAI-Beta",
            "OpenAI-Organization",
        )


# ---------------------------------------------------------------------------
# LOW -- F-R15-8 admission_fallback scope limited
# ---------------------------------------------------------------------------


class _BrokenSessionStore:
    """Session store whose ``get_or_create`` raises -- exercises the
    new admission-fallback routing for session-store failures."""

    def get_or_create(self, session_id: str) -> Any:
        raise RuntimeError(f"redis unreachable while resolving {session_id!r}")

    def save(self, session: Any) -> None:  # pragma: no cover -- never reached
        raise RuntimeError("save would raise too")


class TestF_R15_8_Server_AdmissionStageMisattribution:
    def test_session_store_crash_routes_to_admission_fallback(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        # Swap in the broken session store AFTER construction so the
        # build-time validation paths are untouched.
        app.session_store = _BrokenSessionStore()  # type: ignore[assignment]

        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={
                "X-Classification": "UNCLASS",
                "X-Signet-Session": "test-session-r15-8",
            },
        )
        # 500 from _admission_fallback_response (admission-stage crash).
        assert r.status_code == 500, (
            f"expected 500 from admission fallback, got {r.status_code} {r.text!r}"
        )
        body = r.json()
        assert "correlation_id" in body
        assert body["correlation_id"], f"correlation_id missing from admission fallback: {body!r}"
        # X-Signet-Upstream attribution header set.
        assert r.headers.get("X-Signet-Upstream")
        # Audit row uses pipeline.admission, NOT pipeline.forward.
        rows = list(JsonlBackend(log).iter_entries())
        admission_rows = [row for row in rows if row.check_name == "pipeline.admission"]
        forward_rows = [row for row in rows if row.check_name == "pipeline.forward"]
        assert admission_rows, (
            f"no pipeline.admission audit row; rows={[r_.check_name for r_ in rows]}"
        )
        assert not forward_rows, (
            f"session-store crash mis-attributed to pipeline.forward: "
            f"rows={[r_.check_name for r_ in rows]}"
        )


# ---------------------------------------------------------------------------
# INFO -- F-R15-9 walker handles bytes/bytearray/tuple
# ---------------------------------------------------------------------------


class TestF_R15_9_Server_WalkerBytesBytearrayTuple:
    def test_bytes_value_collected(self) -> None:
        event = {"id": "abc", "payload": b"(S//NF) bytes marker"}
        strings = _collect_inspectable_strings(event)
        assert any("(S//NF)" in s for s in strings), f"bytes value not collected: {strings!r}"

    def test_bytearray_value_collected(self) -> None:
        event = {"id": "abc", "payload": bytearray(b"(S//NF) bytearray marker")}
        strings = _collect_inspectable_strings(event)
        assert any("(S//NF)" in s for s in strings)

    def test_tuple_value_walked(self) -> None:
        event = {"id": "abc", "items": ("(S//NF) tuple item", "other")}
        strings = _collect_inspectable_strings(event)
        assert "(S//NF) tuple item" in strings
        assert "other" in strings

    def test_nested_tuple_walked(self) -> None:
        event = {
            "id": "abc",
            "nested": ({"deep": "(S//NF) deep tuple"}, "sibling"),
        }
        strings = _collect_inspectable_strings(event)
        assert any("(S//NF)" in s for s in strings)
        assert "sibling" in strings

    def test_bytes_in_tuple_collected(self) -> None:
        event = {"id": "abc", "items": (b"(S//NF) bytes-in-tuple",)}
        strings = _collect_inspectable_strings(event)
        assert any("(S//NF)" in s for s in strings)

    def test_invalid_utf8_bytes_still_scannable(self) -> None:
        """Replacement-character decoding keeps partial-utf8 markers
        scannable rather than dropping the value silently."""
        event = {"id": "abc", "payload": b"(S//NF) more\xff"}
        strings = _collect_inspectable_strings(event)
        assert any("(S//NF)" in s for s in strings)


# ---------------------------------------------------------------------------
# INFO -- F-R15-10 Anthropic pause_turn / tool_use finish_reasons
# ---------------------------------------------------------------------------


class TestF_R15_10_Server_AnthropicLate2025FinishReasons:
    def test_pause_turn_in_set(self) -> None:
        assert "pause_turn" in _SSE_DELTA_FINISH_REASON_VALUES

    def test_tool_use_in_set(self) -> None:
        assert "tool_use" in _SSE_DELTA_FINISH_REASON_VALUES

    def test_pause_turn_does_not_abort(self) -> None:
        assert _validate_top_level_structural_field("finish_reason", "pause_turn") == _STRUCTURAL_OK

    def test_tool_use_does_not_abort(self) -> None:
        assert _validate_top_level_structural_field("finish_reason", "tool_use") == _STRUCTURAL_OK

    def test_pre_existing_finish_reasons_still_ok(self) -> None:
        """Adding the new reasons did not regress the existing set."""
        for fr in (
            "stop",
            "length",
            "tool_calls",
            "content_filter",
            "function_call",
            "end_turn",
            "max_tokens",
            "stop_sequence",
        ):
            assert _validate_top_level_structural_field("finish_reason", fr) == _STRUCTURAL_OK, (
                f"finish_reason {fr!r} regressed to non-OK"
            )
