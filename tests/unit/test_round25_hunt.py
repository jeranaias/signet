"""Round 25 hunt closures — regression coverage for F-R25-* findings.

MED:

- ``F-R25-1 _signing_key_id metadata of unhashable type crashes
  verifier``: a tampered JSONL line with ``metadata._signing_key_id =
  [1, 2, 3]`` (or any unhashable JSON value) used to crash
  ``ChainVerifier.verify`` with a raw ``TypeError: unhashable type:
  'list'`` at ``KeyRing.get(<list>)``. ``signet audit verify`` (text
  + JSON modes) inherits the traceback, violating the "structured
  break, never raw traceback" contract that R23-5 closed for top-level
  fields. Post-fix: ``ChainVerifier.verify`` / ``_verify_entry_self``
  validate ``key_id`` is ``str`` before calling ``KeyRing.get`` and
  surface non-string values as a ``BreakKind.MALFORMED_LINE`` break.

- ``F-R25-2 signet replay leaks unsanitized entry_key_id``:
  ``_replay_pretty_print`` interpolated ``entry_key_id`` (pulled from
  attacker-controlled ``metadata[KEY_ID_FIELD]``) into the hmac status
  line WITHOUT ``_sanitize_for_terminal``. Tampered audit row with
  ``_signing_key_id = "\\x1b[2J\\x1bcEVIL"`` leaked literal ANSI bytes
  to the operator's terminal -- same class as the R7 / R14 sanitization
  closures, missed slot. Post-fix: wrap with ``_sanitize_for_terminal``.

LOW:

- ``F-R25-3 approval_chain element types``: ``AuditEntry.from_dict``
  accepted ``approval_chain="alice"`` (string -> tuple of single
  chars) and ``approval_chain=[1, 2, None]`` (mixed types) without
  validation. Post-fix: ``from_dict`` requires list/tuple outer and
  ``str`` elements.

- ``F-R25-4 hmac/prev_hmac length validation``: ``hmac`` / ``prev_hmac``
  were type-checked but not length-validated. The chain writer always
  emits 64-char lowercase hex; a tampered row carrying ``"00"`` or
  ``"0"*1000`` survived ``from_dict`` and only failed downstream at
  ``SELF_MISMATCH``. Post-fix: ``from_dict`` enforces 64 hex chars
  (empty string is preserved as the un-chained sentinel).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from signet.audit.backend import JsonlBackend
from signet.audit.chain import KEY_ID_FIELD, HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import BreakKind, ChainVerifier
from signet.cli import main
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


def _entry(reason: str = "test") -> AuditEntry:
    """Build a fresh AuditEntry with stable owner+check_name+decision."""
    return AuditEntry(
        owner=Owner.human("alice@example.com"),
        check_name="owner_resolution",
        decision=Decision.ALLOW,
        reason=reason,
    )


def _base_entry_dict() -> dict:
    """Build a from_dict-compatible payload with all required fields
    populated to known-good values. Tests mutate one field at a time."""
    return {
        "entry_id": "00000000-0000-0000-0000-000000000000",
        "ts_ns": 1_000_000_000,
        "owner_type": "human",
        "owner_id": "alice",
        "approval_chain": [],
        "decision": "allow",
        "check_name": "test",
        "reason": "",
        "request_fingerprint": "",
        "metadata": {},
        "hmac": "0" * 64,
        "prev_hmac": "0" * 64,
    }


# ---------------------------------------------------------------------------
# MED -- F-R25-1 unhashable _signing_key_id crashes verifier
# ---------------------------------------------------------------------------


class TestF_R25_1_UnhashableKeyIdSurfacesAsStructuredBreak:
    """A tampered ``_signing_key_id`` of unhashable JSON type (list,
    dict) must surface as a structured ``BreakKind.MALFORMED_LINE``
    break, not crash ``ChainVerifier.verify`` with a raw
    ``TypeError: unhashable type`` traceback at
    ``KeyRing.get(<unhashable>)``."""

    @pytest.fixture
    def keyring(self) -> KeyRing:
        return KeyRing(active=Key(key_id="k1", secret=b"x" * 32))

    @pytest.fixture
    def backend(self, tmp_path: Path) -> JsonlBackend:
        return JsonlBackend(tmp_path / "audit.jsonl")

    def _write_tampered_log(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
        bad_key_id_value: object,
    ) -> None:
        """Append two valid entries, then rewrite the second line's
        ``metadata._signing_key_id`` to ``bad_key_id_value``."""
        chain = HmacChain(backend=backend, keyring=keyring)
        chain.append(_entry("first"))
        chain.append(_entry("second"))
        lines = backend.path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[1])
        data["metadata"][KEY_ID_FIELD] = bad_key_id_value
        lines[1] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    @pytest.mark.parametrize(
        "bad_value",
        [
            [1, 2, "list"],
            {"nested": "dict"},
            [],
            {},
        ],
    )
    def test_unhashable_key_id_surfaces_as_malformed_line(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
        bad_value: object,
    ) -> None:
        """Pre-fix: ``ChainVerifier.verify`` crashed with
        ``TypeError: unhashable type`` at ``KeyRing.get(<list>)``.
        Post-fix: emits a structured ``MALFORMED_LINE`` break and the
        report's other entries continue cleanly."""
        self._write_tampered_log(backend, keyring, bad_value)
        # No raw traceback: ``verify()`` returns a structured report.
        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.MALFORMED_LINE in kinds, (
            f"unhashable {KEY_ID_FIELD!r} must surface as MALFORMED_LINE; breaks={report.breaks}"
        )

    def test_hashable_non_string_key_id_also_handled(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
    ) -> None:
        """Hashable-but-wrong-type values (int, None) used to route
        through ``UNKNOWN_KEY`` (``legacy.get(<int>) -> None``). With
        the uniform string check they now route through
        ``MALFORMED_LINE`` -- same routing as the unhashable cases, so
        the schema invariant is uniform: ``_signing_key_id`` is always
        either absent or a ``str``."""
        self._write_tampered_log(backend, keyring, 42)
        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.MALFORMED_LINE in kinds, (
            f"non-string {KEY_ID_FIELD!r} must surface as MALFORMED_LINE; breaks={report.breaks}"
        )

    def test_audit_verify_cli_no_raw_traceback(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """``signet audit verify`` against a tampered log must NOT
        leak a raw ``TypeError`` traceback. The CLI surfaces the
        structured ``MALFORMED_LINE`` break in its report."""
        self._write_tampered_log(backend, keyring, [1, 2, "list"])
        runner = CliRunner()
        # Encode the secret as hex for the CLI flag.
        secret_hex = (b"x" * 32).hex()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(backend.path),
                "--hmac-secret",
                secret_hex,
            ],
        )
        # No raw traceback in stdout/stderr.
        combined = (result.output or "") + (
            "" if result.exception is None else str(result.exception)
        )
        assert "unhashable type" not in combined, (
            f"raw TypeError leaked to CLI output: {combined!r}"
        )
        assert "Traceback" not in combined, f"raw traceback leaked to CLI output: {combined!r}"


# ---------------------------------------------------------------------------
# MED -- F-R25-2 signet replay leaks unsanitized entry_key_id
# ---------------------------------------------------------------------------


class TestF_R25_2_ReplaySanitizesEntryKeyId:
    """``signet replay`` must sanitize ``entry_key_id`` before
    interpolating it into the hmac status line. Pre-fix: a tampered
    audit row with ``_signing_key_id = "\\x1b[2J\\x1bcEVIL"`` leaked
    literal ANSI bytes to the operator's terminal."""

    def test_replay_sanitizes_tampered_signing_key_id(self, tmp_path: Path) -> None:
        """Plant a tampered audit row whose ``_signing_key_id`` contains
        ANSI control bytes. ``signet replay`` with ``--hmac-secret``
        must render those bytes as their textual escape form, not
        leak them to the terminal."""
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        backend = JsonlBackend(log_path)
        chain = HmacChain(backend, keyring)
        appended = chain.append(_entry("with-bytes"))

        # Tamper: replace the signed key_id with ANSI escape bytes.
        # This breaks the HMAC check (the recompute will FAIL
        # verification against ring), but the failure-branch of
        # ``_replay_pretty_print`` ALSO interpolates ``entry_key_id``
        # into ``"  (FAILED verification against ring {entry_key_id})"``,
        # so both code paths are exercised.
        lines = log_path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[0])
        data["metadata"][KEY_ID_FIELD] = "\x1b[2J\x1bcEVIL"
        lines[0] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "replay",
                appended.entry_id,
                "--audit-log",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
            ],
        )
        assert result.exit_code == 0, result.output
        # No literal ESC bytes (0x1B) leak through.
        assert "\x1b" not in result.output, (
            f"raw ESC byte leaked through entry_key_id interpolation: {result.output!r}"
        )
        # The textual escape form shows up instead.
        assert "\\x1b" in result.output, (
            f"sanitizer not applied to entry_key_id; expected "
            f"\\x1b textual escape in output: {result.output!r}"
        )

    def test_replay_sanitizes_verified_branch(self, tmp_path: Path) -> None:
        """The "verified" branch (HMAC matches) ALSO interpolates
        ``entry_key_id``. Forge a row whose hmac actually validates
        but whose ``_signing_key_id`` contains escape bytes. This is
        unreachable in practice (the writer always picks the keyring's
        active id), but defensively the sanitizer should apply to
        both branches. We achieve this by writing a fully-forged
        row whose HMAC is recomputed AFTER the metadata mutation, so
        the verify branch is taken."""
        import hashlib
        import hmac as _hmac

        from signet.audit.chain import _serialize_for_signing

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32

        # Build an entry whose ``_signing_key_id`` carries ANSI bytes.
        evil_key_id = "\x1b]0;EVIL\x07"
        entry = AuditEntry(
            owner=Owner.human("alice"),
            check_name="check",
            decision=Decision.ALLOW,
            reason="r",
            metadata={KEY_ID_FIELD: evil_key_id},
            entry_id="11111111-1111-1111-1111-111111111111",
            ts_ns=1_000_000_000,
            prev_hmac="",
            hmac="",
        )
        payload = _serialize_for_signing(entry)
        digest = _hmac.new(secret, payload, hashlib.sha256).hexdigest()
        linked = entry.with_chain_links(prev_hmac="", hmac=digest)
        log_path.write_text(
            json.dumps(linked.to_dict(), separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "replay",
                linked.entry_id,
                "--audit-log",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
            ],
        )
        assert result.exit_code == 0, result.output
        # No literal ESC / BEL leak through.
        assert "\x1b" not in result.output
        assert "\x07" not in result.output
        # The verified branch is taken (HMAC matched), and entry_key_id
        # is sanitized so the textual escape shows up.
        assert "verified against ring" in result.output
        assert "\\x1b" in result.output


# ---------------------------------------------------------------------------
# LOW -- F-R25-3 approval_chain element validation
# ---------------------------------------------------------------------------


class TestF_R25_3_ApprovalChainElementValidation:
    """``AuditEntry.from_dict`` must validate ``approval_chain`` is a
    list/tuple of strings. Pre-fix it accepted ``"alice"`` (string ->
    tuple of single chars) and ``[1, 2, None]`` (mixed types)."""

    def test_string_outer_rejected(self) -> None:
        bad = _base_entry_dict()
        bad["approval_chain"] = "alice"
        with pytest.raises(TypeError, match="approval_chain"):
            AuditEntry.from_dict(bad)

    @pytest.mark.parametrize(
        "bad_outer",
        [
            42,
            None,
            {"k": "v"},
            3.14,
            True,
        ],
    )
    def test_non_list_outer_rejected(self, bad_outer: object) -> None:
        bad = _base_entry_dict()
        bad["approval_chain"] = bad_outer
        with pytest.raises(TypeError, match="approval_chain"):
            AuditEntry.from_dict(bad)

    @pytest.mark.parametrize(
        "bad_chain",
        [
            [42],
            ["alice", 42],
            ["alice", None],
            ["alice", {"nested": "dict"}],
            [None],
            [{"k": "v"}],
        ],
    )
    def test_non_string_element_rejected(self, bad_chain: list) -> None:
        bad = _base_entry_dict()
        bad["approval_chain"] = bad_chain
        with pytest.raises(TypeError, match="approval_chain"):
            AuditEntry.from_dict(bad)

    def test_valid_string_list_accepted(self) -> None:
        """The happy path still works -- a list of strings round-trips
        to a tuple of strings on the ``Owner``."""
        good = _base_entry_dict()
        good["approval_chain"] = ["alice", "bob", "carol"]
        entry = AuditEntry.from_dict(good)
        assert entry.owner.approval_chain == ("alice", "bob", "carol")

    def test_empty_list_accepted(self) -> None:
        good = _base_entry_dict()
        good["approval_chain"] = []
        entry = AuditEntry.from_dict(good)
        assert entry.owner.approval_chain == ()

    def test_missing_approval_chain_defaults_to_empty(self) -> None:
        """``approval_chain`` is optional; absent defaults to empty
        tuple (preserved from R23 baseline)."""
        good = _base_entry_dict()
        del good["approval_chain"]
        entry = AuditEntry.from_dict(good)
        assert entry.owner.approval_chain == ()


# ---------------------------------------------------------------------------
# LOW -- F-R25-4 hmac/prev_hmac length validation
# ---------------------------------------------------------------------------


class TestF_R25_4_HmacLengthValidation:
    """``AuditEntry.from_dict`` must reject ``hmac`` / ``prev_hmac``
    values that aren't exactly 64 lowercase-hex chars. The chain
    writer always emits ``hashlib.sha256().hexdigest()`` (64 hex
    chars); a tampered row carrying any other length is malformed."""

    @pytest.mark.parametrize(
        "field",
        ["hmac", "prev_hmac"],
    )
    @pytest.mark.parametrize(
        "bad_length_value",
        [
            "00",
            "0" * 63,
            "0" * 65,
            "0" * 1000,
            "abc",
        ],
    )
    def test_wrong_length_rejected(self, field: str, bad_length_value: str) -> None:
        bad = _base_entry_dict()
        bad[field] = bad_length_value
        with pytest.raises(ValueError, match=field):
            AuditEntry.from_dict(bad)

    @pytest.mark.parametrize(
        "field",
        ["hmac", "prev_hmac"],
    )
    def test_non_hex_chars_rejected(self, field: str) -> None:
        bad = _base_entry_dict()
        # 64-char string, but contains a non-hex char.
        bad[field] = "g" * 64
        with pytest.raises(ValueError, match=field):
            AuditEntry.from_dict(bad)

    @pytest.mark.parametrize(
        "field",
        ["hmac", "prev_hmac"],
    )
    def test_uppercase_hex_rejected(self, field: str) -> None:
        """The writer always emits lowercase hex (``hexdigest()`` is
        lowercase by spec). Uppercase is technically valid hex but
        the schema rejects it for invariant uniformity."""
        bad = _base_entry_dict()
        bad[field] = "A" * 64
        with pytest.raises(ValueError, match=field):
            AuditEntry.from_dict(bad)

    @pytest.mark.parametrize(
        "field",
        ["hmac", "prev_hmac"],
    )
    def test_empty_string_preserved_as_unchained_sentinel(self, field: str) -> None:
        """An un-chained entry (newly constructed, not yet written by
        the chain writer) legitimately has empty ``hmac`` /
        ``prev_hmac``. The length validator must preserve this
        sentinel."""
        good = _base_entry_dict()
        good[field] = ""
        # Should not raise.
        entry = AuditEntry.from_dict(good)
        assert getattr(entry, field) == ""

    def test_valid_64char_hex_accepted(self) -> None:
        """The happy path: real chain-writer output round-trips."""
        good = _base_entry_dict()
        good["hmac"] = "0123456789abcdef" * 4  # 64 chars, valid hex
        good["prev_hmac"] = "f" * 64
        entry = AuditEntry.from_dict(good)
        assert entry.hmac == "0123456789abcdef" * 4
        assert entry.prev_hmac == "f" * 64


# ---------------------------------------------------------------------------
# Integration: tampered log routes through MalformedAuditEntry
# (defense-in-depth check that the new validations actually surface
# through ``JsonlBackend.iter_entries -> ChainVerifier`` as the
# documented ``BreakKind.MALFORMED_LINE``).
# ---------------------------------------------------------------------------


class TestF_R25_3_TamperedApprovalChainSurfacesAsMalformedLine:
    """A tampered audit log whose ``approval_chain`` is mutated to a
    non-list outer type must surface as ``MALFORMED_LINE`` through
    the normal ``JsonlBackend.iter_entries`` -> ``ChainVerifier``
    pipeline, matching the routing of the other R23-5 / R25-3 type
    rejections."""

    def test_tampered_approval_chain_routes_to_malformed_line(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        backend = JsonlBackend(log_path)
        chain = HmacChain(backend, keyring)
        chain.append(_entry("first"))
        chain.append(_entry("second"))

        # Tamper line 2: approval_chain becomes the string "alice".
        lines = log_path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[1])
        data["approval_chain"] = "alice"
        lines[1] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.MALFORMED_LINE in kinds, (
            f"tampered approval_chain must surface as MALFORMED_LINE; breaks={report.breaks}"
        )


class TestF_R25_4_TamperedHmacLengthSurfacesAsMalformedLine:
    """A tampered audit log whose ``hmac`` is mutated to a wrong-length
    string must surface as ``MALFORMED_LINE`` (the new
    ``ValueError`` from ``from_dict`` is routed through
    ``MalformedAuditEntry`` by ``JsonlBackend.iter_entries`` just
    like the other schema rejections)."""

    def test_tampered_short_hmac_routes_to_malformed_line(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        backend = JsonlBackend(log_path)
        chain = HmacChain(backend, keyring)
        chain.append(_entry("first"))
        chain.append(_entry("second"))

        # Tamper line 2: hmac becomes "00" (way too short).
        lines = log_path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[1])
        data["hmac"] = "00"
        lines[1] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.MALFORMED_LINE in kinds, (
            f"tampered short hmac must surface as MALFORMED_LINE; breaks={report.breaks}"
        )


# ---------------------------------------------------------------------------
# Plugin discovery EP-surface closures (F-R25-1/2/3/4/5/6/7).
# R24 hardened the resolved-object surface; R25 found the EntryPoint /
# Distribution providers have the same hostile-metaclass + str-subclass
# attack class. ``_safe_str_attr`` returns a plain ``str`` regardless
# of subclass, so downstream consumers (dict keys, ``or`` fallbacks,
# ``len``, f-strings) never invoke a hostile dunder.
# ---------------------------------------------------------------------------


class TestF_R25_PluginEpSafeStrAttr:
    def test_returns_plain_str_when_property_raises(self) -> None:
        from signet.plugins.discovery import _safe_str_attr

        class _Hostile:
            @property
            def name(self) -> str:
                raise RuntimeError("hostile @property")

        result = _safe_str_attr(_Hostile(), "name", default="fallback")
        assert result == "fallback"
        assert type(result) is str

    def test_returns_plain_str_for_str_subclass_with_raising_bool(self) -> None:
        from signet.plugins.discovery import _safe_str_attr

        class _RaisingBoolStr(str):
            def __bool__(self) -> bool:
                raise RuntimeError("hostile __bool__")

        class _Provider:
            name = _RaisingBoolStr("legit-name")

        result = _safe_str_attr(_Provider(), "name", default="")
        assert type(result) is str
        assert result == "legit-name"
        # The hostile __bool__/__len__/__hash__ must NOT crash these:
        assert bool(result) is True
        assert len(result) == 10
        assert hash(result) is not None

    def test_returns_plain_str_for_str_subclass_with_raising_len(self) -> None:
        from signet.plugins.discovery import _safe_str_attr

        class _RaisingLenStr(str):
            def __len__(self) -> int:
                raise RuntimeError("hostile __len__")

        class _Provider:
            value = _RaisingLenStr("legit-target")

        result = _safe_str_attr(_Provider(), "value", default="")
        assert type(result) is str
        assert len(result) == 12

    def test_returns_plain_str_for_str_subclass_with_raising_hash(self) -> None:
        from signet.plugins.discovery import _safe_str_attr

        class _RaisingHashStr(str):
            def __hash__(self) -> int:
                raise RuntimeError("hostile __hash__")

        class _Provider:
            name = _RaisingHashStr("legit-name")

        result = _safe_str_attr(_Provider(), "name", default="")
        assert type(result) is str
        # Dict assignment must work without invoking the subclass hash:
        d = {result: "ok"}
        assert d[result] == "ok"

    def test_returns_plain_str_for_non_str_return(self) -> None:
        from signet.plugins.discovery import _safe_str_attr

        class _Provider:
            name = 42

        result = _safe_str_attr(_Provider(), "name", default="fallback")
        # Plain ``str`` instance, no crash.
        assert type(result) is str

    def test_discovered_plugin_post_init_handles_str_subclass(self) -> None:
        """``DiscoveredPlugin.__post_init__`` previously crashed on a
        ``str``-subclass with raising ``__len__``. Now coerces via
        ``_safe_str_attr`` before truncation."""
        from signet.plugins.discovery import DiscoveredPlugin

        class _RaisingLenStr(str):
            def __len__(self) -> int:
                raise RuntimeError("hostile __len__")

        plugin = DiscoveredPlugin(
            group="signet.checks",
            name=_RaisingLenStr("plugin-name"),
            package=_RaisingLenStr("pkg"),
            package_version=_RaisingLenStr("0.1.0"),
            target=_RaisingLenStr("mod:Cls"),
            status="load_error",
            abi_declared=None,
            abi_required=1,
            error="test",
            obj=None,
        )
        assert type(plugin.name) is str
        assert type(plugin.package) is str
        assert type(plugin.package_version) is str
        assert type(plugin.target) is str
        assert len(plugin.name) == 11
