"""Tests for the signet CLI.

Use click's CliRunner to invoke commands in-process. No subprocess; the
CLI module is exercised end-to-end except for the actual uvicorn.run()
call, which is tested by Wave 5's TestClient suite.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.cli import main
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


class TestVersion:
    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "signet" in result.output


class TestInit:
    def test_init_creates_files(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "pipeline.py").exists()
        assert (tmp_path / ".env.example").exists()
        # .gitignore is generated so users do not commit their HMAC
        # secret or audit log on first push.
        gi = tmp_path / ".gitignore"
        assert gi.exists()
        text = gi.read_text(encoding="utf-8")
        assert ".env" in text
        assert "*.jsonl" in text

    def test_init_does_not_overwrite_existing_gitignore(self, tmp_path: Path) -> None:
        gi = tmp_path / ".gitignore"
        gi.write_text("# user-managed\n", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert gi.read_text(encoding="utf-8") == "# user-managed\n"


class TestHexSecretParsing:
    def test_audit_verify_clear_error_for_bad_hex(self, tmp_path: Path) -> None:
        # Pre-create a non-empty audit log so click's exists=True passes
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("{}\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                "not-real-hex",
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code != 0
        assert "not valid hex" in result.output
        assert "openssl rand -hex 32" in result.output

    def test_audit_verify_clear_error_for_short_hex(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("{}\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                "abcd",  # 2 bytes, way too short
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code != 0
        assert "too short" in result.output.lower() or "needs at least" in result.output

    def test_init_writes_client_example(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0
        client = tmp_path / "client_example.py"
        assert client.exists()
        text = client.read_text(encoding="utf-8")
        assert "X-Commit-Owner" in text
        assert "wrap_openai" in text


class TestDevShorthand:
    def test_dev_flag_implies_ephemeral_audit_and_pipeline(self, tmp_path: Path) -> None:
        """--dev should fill in --allow-ephemeral-key, --audit-log, and --config
        if a pipeline.py exists in cwd."""
        runner = CliRunner()
        # init scaffolds pipeline.py into cwd
        with runner.isolated_filesystem(temp_dir=tmp_path):
            init = runner.invoke(main, ["init", "."])
            assert init.exit_code == 0, init.output
            # We can't easily run the server (uvicorn would block), but
            # we can patch uvicorn.run and confirm the config we built.
            captured: dict[str, object] = {}

            def fake_run(app, **kwargs):
                captured["called"] = True
                captured["kwargs"] = kwargs

            import sys as _sys

            class _FakeUvicorn:
                run = staticmethod(fake_run)

            real_uvicorn = _sys.modules.get("uvicorn")
            _sys.modules["uvicorn"] = _FakeUvicorn  # type: ignore[assignment]
            try:
                result = runner.invoke(
                    main,
                    ["serve", "--upstream", "http://upstream-mock/v1", "--dev"],
                )
            finally:
                if real_uvicorn is not None:
                    _sys.modules["uvicorn"] = real_uvicorn
                else:
                    _sys.modules.pop("uvicorn", None)
            assert result.exit_code == 0, result.output
            assert captured.get("called") is True
            # Ephemeral key warning fires + key bytes printed
            assert "EPHEMERAL HMAC KEY" in result.output
            # Pipeline checks listed (the scaffold has 6+ checks)
            assert "pipeline (" in result.output


class TestAuditShowAlias:
    def test_audit_show_works(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        appended = chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", "show", appended.entry_id, "--audit-log", str(log_path)],
        )
        assert result.exit_code == 0, result.output
        assert appended.entry_id in result.output
        assert "alice" in result.output

    def test_replay_promoted_to_first_class_no_deprecation_warning(
        self, tmp_path: Path
    ) -> None:
        """v0.1.6 F2 promoted ``signet replay`` to first-class. The old
        v0.1.0 deprecation warning has been retired; the command is now
        the recommended UX. ``signet audit show`` continues to work as
        the canonical alias.
        """
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        appended = chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        runner = CliRunner()
        result = runner.invoke(main, ["replay", appended.entry_id, "--audit-log", str(log_path)])
        assert result.exit_code == 0, result.output
        # Output prints the entry pretty-formatted and does NOT emit
        # the v0.1.0 deprecation warning anymore.
        assert appended.entry_id in result.output
        assert "deprecated" not in result.output.lower()


class TestKeysGenerateEd25519:
    def test_generate_writes_priv_and_pub(self, tmp_path: Path) -> None:
        runner = CliRunner()
        priv_path = tmp_path / "signet.key"
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(priv_path),
                "--key-id",
                "smoketest",
            ],
        )
        assert result.exit_code == 0, result.output
        assert priv_path.exists()
        pub_path = tmp_path / "signet.key.pub"
        assert pub_path.exists()
        # Both files are PEM-encoded
        assert b"-----BEGIN PRIVATE KEY-----" in priv_path.read_bytes()
        assert b"-----BEGIN PUBLIC KEY-----" in pub_path.read_bytes()

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        priv_path = tmp_path / "signet.key"
        priv_path.write_text("existing", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["keys", "generate-ed25519", "--out", str(priv_path)],
        )
        assert result.exit_code != 0
        assert "refusing to overwrite" in result.output

    def test_force_overwrites(self, tmp_path: Path) -> None:
        priv_path = tmp_path / "signet.key"
        priv_path.write_text("existing", encoding="utf-8")
        pub_path = tmp_path / "signet.key.pub"
        pub_path.write_text("existing-pub", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["keys", "generate-ed25519", "--out", str(priv_path), "--force"],
        )
        assert result.exit_code == 0
        assert b"-----BEGIN PRIVATE KEY-----" in priv_path.read_bytes()


class TestLint:
    """v0.1.5 #9: static analysis on a pipeline.py."""

    _GOOD_PIPELINE = """
from signet.checks import (OwnerResolutionCheck, RateLimitCheck,
    ClassificationGateCheck, ScopeDriftCheck)
from signet.core.pipeline import Pipeline
pipeline = Pipeline(checks=[
    OwnerResolutionCheck(require_owner=True),
    ClassificationGateCheck(),
    RateLimitCheck(capacity=60, refill_per_second=1.0),
    ScopeDriftCheck(),
])
"""

    _BAD_PIPELINE = """
from signet.checks import (RateLimitCheck, ClassificationGateCheck,
    ToolCallInspectorCheck)
from signet.core.pipeline import Pipeline
pipeline = Pipeline(checks=[
    RateLimitCheck(capacity=60, refill_per_second=1.0),
    ClassificationGateCheck(),
    ToolCallInspectorCheck(allow_unregistered=True),
])
"""

    def test_lint_clean_pipeline_passes(self, tmp_path: Path) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(self._GOOD_PIPELINE, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_lint_flags_missing_owner_resolution(self, tmp_path: Path) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(self._BAD_PIPELINE, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        # SIG002 is severity=error → exit 1 even without --strict.
        assert result.exit_code == 1
        assert "SIG002" in result.output  # missing OwnerResolution
        assert "SIG003" in result.output  # allow_unregistered=True
        assert "SIG004" in result.output  # ClassGate w/o ScopeDrift

    def test_strict_promotes_warnings_to_failure(self, tmp_path: Path) -> None:
        # Warnings only: ClassificationGate without ScopeDrift (SIG004),
        # but include OwnerResolution so SIG002 doesn't fire.
        path = tmp_path / "pipeline.py"
        path.write_text(
            "\nfrom signet.checks import OwnerResolutionCheck, "
            "ClassificationGateCheck\n"
            "from signet.core.pipeline import Pipeline\n"
            "pipeline = Pipeline(checks=[\n"
            "    OwnerResolutionCheck(),\n"
            "    ClassificationGateCheck(),\n"
            "])\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result_default = runner.invoke(main, ["lint", str(path)])
        assert result_default.exit_code == 0  # warnings only
        assert "SIG004" in result_default.output

        result_strict = runner.invoke(main, ["lint", str(path), "--strict"])
        assert result_strict.exit_code == 1


class TestDoctor:
    def test_doctor_with_no_flags_prints_versions(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
        assert result.exit_code == 0
        assert "signet" in result.output
        assert "python" in result.output
        assert "httpx" in result.output

    def test_doctor_unreachable_upstream_fails(self) -> None:
        runner = CliRunner()
        # Deliberately unroutable port — should fail the probe.
        result = runner.invoke(main, ["doctor", "--upstream", "http://127.0.0.1:1/v1"])
        assert result.exit_code == 1
        assert "unreachable" in result.output.lower()

    def test_audit_verify_strips_whitespace_and_0x_prefix(self, tmp_path: Path) -> None:
        # Build a real chain so the verifier has something to walk
        from signet.audit.backend import JsonlBackend
        from signet.audit.chain import HmacChain
        from signet.audit.keyring import Key, KeyRing
        from signet.core.audit import AuditEntry, Decision
        from signet.core.owner import Owner

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        ring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), ring)
        chain.append(
            AuditEntry(
                owner=Owner.human("a"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                f"  0x{secret.hex()}  ",
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "OK:" in result.output

    def test_init_refuses_overwrite(self, tmp_path: Path) -> None:
        # v0.1.7 (C2): init now does partial-write-skip-existing — when
        # ``pipeline.py`` exists alone, the other files are still
        # written and the existing pipeline.py is preserved unchanged
        # with a "skipped (already exists)" note. Only when every
        # scaffolded file exists does init refuse with exit code 1.
        original = "# pre-existing"
        (tmp_path / "pipeline.py").write_text(original, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "skipped (already exists)" in result.output
        # The pre-existing file must NOT have been overwritten.
        assert (tmp_path / "pipeline.py").read_text(encoding="utf-8") == original
        # And the other files must have been scaffolded.
        assert (tmp_path / ".env.example").exists()
        assert (tmp_path / "client_example.py").exists()

    def test_init_scaffold_imports_cleanly(self, tmp_path: Path) -> None:
        """The starter pipeline.py must be valid Python that imports cleanly."""
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0

        import importlib.util

        spec = importlib.util.spec_from_file_location("user_pipeline", tmp_path / "pipeline.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert hasattr(module, "pipeline")


class TestAuditVerify:
    def test_verify_clean_chain(self, tmp_path: Path) -> None:
        # Set up a real chain with two entries
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="owner_resolution",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="rate_limit",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "OK: 2 entries" in result.output

    def test_verify_tampered_chain_exits_2(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        # Tamper: corrupt the log
        text = log_path.read_text(encoding="utf-8")
        log_path.write_text(text.replace("alice", "mallory"), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code == 2
        assert "BROKEN" in result.output


class TestReplay:
    def test_replay_existing_entry(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        appended = chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="owner_resolution",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["replay", appended.entry_id, "--audit-log", str(log_path)])
        assert result.exit_code == 0, result.output
        assert appended.entry_id in result.output
        assert "alice" in result.output

    def test_replay_case_insensitive_uuid(self, tmp_path: Path) -> None:
        """UUIDs are case-insensitive per RFC 4122; operators paste from
        logs that may render them as upper or mixed case. Compare must
        normalize both sides."""
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        appended = chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        # Try the upper-cased form; should still find it.
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["replay", appended.entry_id.upper(), "--audit-log", str(log_path)],
        )
        assert result.exit_code == 0, result.output

    def test_replay_missing_entry_exits_1(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.touch()

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["replay", "00000000-0000-0000-0000-000000000000", "--audit-log", str(log_path)],
        )
        assert result.exit_code == 1
        assert "no entry with id" in result.output


class TestReplayFirstClass:
    """v0.1.6 F2: signet replay <id> is the operator's primary
    incident-response surface. Pretty-prints the audit row with field
    labels aligned, optionally verifies the HMAC against the active
    key.
    """

    def _build_log_with_entries(self, log_path: Path, secret: bytes) -> list[AuditEntry]:
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        appended = []
        for name, owner_principal in (
            ("owner_resolution", "alice"),
            ("rate_limit", "bob"),
            ("prompt_injection", "carol"),
        ):
            appended.append(
                chain.append(
                    AuditEntry(
                        owner=Owner.human(owner_principal),
                        check_name=name,
                        decision=Decision.ALLOW,
                        reason="ok",
                    )
                )
            )
        return appended

    def test_replay_pretty_prints_each_entry(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        entries = self._build_log_with_entries(log_path, secret)

        runner = CliRunner()
        for entry in entries:
            result = runner.invoke(
                main,
                ["replay", entry.entry_id, "--audit-log", str(log_path)],
            )
            assert result.exit_code == 0, result.output
            assert entry.entry_id in result.output
            assert "entry_id:" in result.output
            assert "decision:" in result.output
            assert "hmac:" in result.output
            assert entry.check_name in result.output

    def test_replay_id_not_found_exits_1(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.touch()
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["replay", "00000000-0000-0000-0000-000000000000", "--audit-log", str(log_path)],
        )
        assert result.exit_code == 1
        assert "no entry with id" in result.output

    def test_replay_audit_log_flag_overrides_default(self, tmp_path: Path) -> None:
        # Default --audit-log is ``./audit.jsonl``; here we pass a
        # file in a different directory and confirm it's used.
        custom = tmp_path / "elsewhere.jsonl"
        secret = b"x" * 32
        entries = self._build_log_with_entries(custom, secret)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["replay", entries[0].entry_id, "--audit-log", str(custom)],
        )
        assert result.exit_code == 0, result.output

    def test_replay_with_hmac_secret_marks_verified(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        entries = self._build_log_with_entries(log_path, secret)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "replay",
                entries[0].entry_id,
                "--audit-log",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "verified against ring k1" in result.output


class TestLintSIG001:
    """v0.1.6 F6: SIG001 was repurposed. It now fires when
    RateLimitCheck is constructed with an explicit priority < 100.
    Default priority (100) does NOT fire.
    """

    _PIPELINE_DEFAULT_PRIORITY = """
from signet.checks import (OwnerResolutionCheck, RateLimitCheck,
    ScopeDriftCheck, ClassificationGateCheck)
from signet.core.pipeline import Pipeline
pipeline = Pipeline(checks=[
    OwnerResolutionCheck(require_owner=True),
    ClassificationGateCheck(),
    RateLimitCheck(capacity=60, refill_per_second=1.0),
    ScopeDriftCheck(),
])
"""

    _PIPELINE_PRIORITY_OVERRIDE = """
from signet.checks import (OwnerResolutionCheck, RateLimitCheck,
    ScopeDriftCheck, ClassificationGateCheck)
from signet.core.pipeline import Pipeline


class EarlyRateLimitCheck(RateLimitCheck):
    priority = 10  # explicit override, < 100, the v0.1.4 footgun


pipeline = Pipeline(checks=[
    OwnerResolutionCheck(require_owner=True),
    ClassificationGateCheck(),
    EarlyRateLimitCheck(capacity=60, refill_per_second=1.0),
    ScopeDriftCheck(),
])
"""

    def test_sig001_does_not_fire_with_default_priority(self, tmp_path: Path) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(self._PIPELINE_DEFAULT_PRIORITY, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        assert result.exit_code == 0, result.output
        assert "SIG001" not in result.output

    def test_sig001_fires_on_explicit_priority_override(self, tmp_path: Path) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(self._PIPELINE_PRIORITY_OVERRIDE, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        # Severity is warning -> exit 0 without --strict, but the
        # finding text is rendered.
        assert "SIG001" in result.output
        assert "priority=10" in result.output


class TestProbeInjection:
    """v0.1.6 N1: ``signet doctor --probe-injection`` ships with a
    static obfuscated-injection corpus. We don't run a full integration
    here (would require booting a real signet proxy); we test the
    observable contract: corpus content + missing-target error.
    """

    def test_corpus_loadable_and_documented(self) -> None:
        from signet.cli_helpers.probe_injection_corpus import (
            PROMPT_INJECTION_PROBE_CORPUS,
        )

        names = {p.name for p in PROMPT_INJECTION_PROBE_CORPUS}
        # Every documented probe class must be present.
        assert "plain_ignore_previous" in names
        assert "cyrillic_confusable" in names
        assert "stretched_whitespace" in names
        assert "zero_width_inserts" in names
        assert "base64_encoded" in names
        assert "rot13_encoded" in names
        assert "base32_encoded" in names
        assert "hex_encoded" in names
        assert "dan_persona_attack" in names
        # Every probe carries the documented metadata fields with
        # plausible values.
        for p in PROMPT_INJECTION_PROBE_CORPUS:
            assert p.payload.strip()
            assert p.expected_match_source
            assert p.severity == "high"

    def test_probe_injection_without_self_errors(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["doctor", "--probe-injection"])
        # Without --self the command refuses with a useful message.
        assert result.exit_code == 1
        assert "--self" in result.output
        assert "probe-injection" in result.output


class TestPluginsList:
    """v0.1.6 A1: ``signet plugins list`` enumerates entry points and
    reports load status.
    """

    def _stub_plugins(self):
        from signet.plugins.discovery import DiscoveredPlugin

        return [
            DiscoveredPlugin(
                group="signet.checks",
                name="geopolitical_compliance",
                package="thornveil-extras",
                package_version="0.2.1",
                target="thornveil_extras.geo:GeoCheck",
                status="loaded",
                abi_declared=1,
                abi_required=1,
                error=None,
                obj=object,
            ),
            DiscoveredPlugin(
                group="signet.checks",
                name="future_thing",
                package="future-pkg",
                package_version="0.0.1",
                target="future_pkg.thing:FutureCheck",
                status="incompatible_abi",
                abi_declared=99,
                abi_required=1,
                error="declares CHECK_ABI_VERSION=99; signet requires 1",
                obj=None,
            ),
            DiscoveredPlugin(
                group="signet.adapters",
                name="openai_pinned",
                package="signet-extras",
                package_version="0.5.0",
                target="signet_extras.adapters:OpenAIPinnedAdapter",
                status="loaded",
                abi_declared=None,
                abi_required=1,
                error=None,
                obj=object,
            ),
        ]

    def test_plugins_list_text_output(self, monkeypatch) -> None:
        plugins = self._stub_plugins()
        # Patch the symbol the CLI imports lazily inside plugins_list.
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "list"])
        assert result.exit_code == 0, result.output
        # Section headers + plugin names visible.
        assert "INSTALLED CHECKS (2)" in result.output
        assert "INSTALLED ADAPTERS (1)" in result.output
        assert "INSTALLED ANCHORS (0)" in result.output
        assert "geopolitical_compliance" in result.output
        assert "future_thing" in result.output
        assert "openai_pinned" in result.output
        assert "incompatible_abi" in result.output

    def test_plugins_list_json_output(self, monkeypatch) -> None:
        import json

        plugins = self._stub_plugins()
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "list", "--json"])
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 3
        names = {row["name"] for row in parsed}
        assert names == {"geopolitical_compliance", "future_thing", "openai_pinned"}

    def test_plugins_list_group_filter(self, monkeypatch) -> None:
        plugins = self._stub_plugins()
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["plugins", "list", "--group", "signet.checks"]
        )
        assert result.exit_code == 0, result.output
        assert "INSTALLED CHECKS (2)" in result.output
        # Adapters should be filtered out -- we did not pass --group all.
        assert "INSTALLED ADAPTERS" not in result.output
        assert "openai_pinned" not in result.output


class TestAuditCompact:
    """v0.1.6 A2: ``signet audit compact`` Merkle-archives a prefix of
    the chain. Tests cover quiesce-confirm refusal, the no-op path, and
    a successful round-trip that verifies cleanly with
    ``--including-archives``.
    """

    def _build_chain_with_entries(self, log_path: Path, secret: bytes, n: int):
        from datetime import UTC, datetime

        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        # Stagger ts_ns so the cutoff can split them deterministically.
        # We do it via direct AuditEntry construction.
        appended: list[AuditEntry] = []
        base_ts = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1e9)
        for i in range(n):
            entry = AuditEntry(
                owner=Owner.human(f"u{i}"),
                check_name="owner_resolution",
                decision=Decision.ALLOW,
                reason="ok",
                ts_ns=base_ts + i * 1_000_000_000,  # 1s apart
            )
            appended.append(chain.append(entry))
        return appended

    def test_compact_refuses_without_quiesce_confirm(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain_with_entries(log_path, secret, 3)
        archive = tmp_path / "archive.bin"

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                "2030-01-01T00:00:00Z",
                "--output",
                str(archive),
                "--hmac-secret",
                secret.hex(),
            ],
        )
        assert result.exit_code != 0
        assert "--quiesce-confirm" in result.output
        # Archive must NOT have been written.
        assert not archive.exists()

    def test_compact_no_op_when_nothing_eligible(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain_with_entries(log_path, secret, 3)
        archive = tmp_path / "archive.bin"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                "2000-01-01T00:00:00Z",  # earlier than every entry
                "--output",
                str(archive),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "no-op" in result.output
        # No archive written on the no-op path.
        assert not archive.exists()

    def test_compact_round_trip_verifies(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        entries = self._build_chain_with_entries(log_path, secret, 5)
        # Cutoff between entry 2 and entry 3.
        from datetime import UTC, datetime

        cutoff_ts_ns = entries[3].ts_ns
        cutoff_dt = datetime.fromtimestamp(cutoff_ts_ns / 1e9, tz=UTC)
        cutoff_iso = cutoff_dt.isoformat().replace("+00:00", "Z")

        archive = tmp_path / "archive.bin"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                cutoff_iso,
                "--output",
                str(archive),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "compaction complete" in result.output
        assert archive.exists()

        # ``audit verify --including-archives`` must succeed.
        verify = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--including-archives",
                str(archive.parent),
            ],
        )
        assert verify.exit_code == 0, verify.output
        assert "OK:" in verify.output

    def test_verify_including_archives_detects_tampered_archive(
        self, tmp_path: Path
    ) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        entries = self._build_chain_with_entries(log_path, secret, 5)
        from datetime import UTC, datetime

        cutoff_ts_ns = entries[3].ts_ns
        cutoff_iso = (
            datetime.fromtimestamp(cutoff_ts_ns / 1e9, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        archive = tmp_path / "archive.bin"
        runner = CliRunner()
        compact = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                cutoff_iso,
                "--output",
                str(archive),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
            ],
        )
        assert compact.exit_code == 0, compact.output

        # Tamper: corrupt the Merkle blob's stored root region. The
        # archive layout puts the Merkle tree's serialized form between
        # ``MERKLE-START\n`` and ``\nMERKLE-END\n``; the last bytes
        # before ``MERKLE-END`` are the hex-encoded root. Flipping one
        # of those bytes makes ``MerkleTree.deserialize`` fail with
        # "stored root does not match recomputed root", which the
        # verifier surfaces as ARCHIVE_FORMAT_INVALID.
        raw = archive.read_bytes()
        tampered = bytearray(raw)
        end = raw.find(b"\nMERKLE-END\n")
        assert end != -1
        # Flip a byte two positions before MERKLE-END -- comfortably
        # inside the stored hex root.
        tampered[end - 2] ^= 0x01
        archive.write_bytes(bytes(tampered))

        verify = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--including-archives",
                str(archive.parent),
            ],
        )
        # A tampered archive must trigger a non-zero exit. The exact
        # break kind depends on which byte we hit (ARCHIVE_FORMAT_INVALID
        # or MERKLE_MISMATCH), but the operator-facing signal is the
        # same: non-zero exit + "BROKEN" in the output.
        assert verify.exit_code == 2, verify.output
        assert "BROKEN" in verify.output


class TestAuditReport:
    """v0.1.6 A4: ``signet audit report`` rolls a window of audit
    entries up into the operator-facing summary.
    """

    def _build_mixed_chain(self, log_path: Path, secret: bytes) -> None:
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        # Mix decisions and checks. Most entries are recent; a couple
        # in the prior window to exercise the deltas section.
        import time

        now_ns = time.time_ns()
        layouts = [
            (Owner.human("alice"), "owner_resolution", Decision.ALLOW, "ok", now_ns - 5 * 60 * 1_000_000_000),
            (Owner.human("bob"), "rate_limit", Decision.ALLOW, "ok", now_ns - 4 * 60 * 1_000_000_000),
            (Owner.human("alice"), "prompt_injection", Decision.BLOCK, "blocked", now_ns - 3 * 60 * 1_000_000_000),
            (Owner.human("alice"), "prompt_injection", Decision.BLOCK, "blocked", now_ns - 2 * 60 * 1_000_000_000),
            (Owner.human("eve"), "tool_call_inspector", Decision.ESCALATE, "escalate", now_ns - 1 * 60 * 1_000_000_000),
        ]
        for owner, check, decision, reason, ts in layouts:
            chain.append(
                AuditEntry(
                    owner=owner,
                    check_name=check,
                    decision=decision,
                    reason=reason,
                    ts_ns=ts,
                )
            )

    def test_report_markdown_contains_expected_sections(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_mixed_chain(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--anonymize-salt",
                "test-salt",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "# signet audit report" in result.output
        assert "## Decision distribution" in result.output
        assert "## Top firing checks" in result.output
        assert "Total decisions" in result.output
        # block decisions exist -> top firing checks must list
        # prompt_injection.
        assert "prompt_injection" in result.output

    def test_report_json_format_parses(self, tmp_path: Path) -> None:
        import json

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_mixed_chain(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--format",
                "json",
                "--anonymize-salt",
                "test-salt",
            ],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert "range" in parsed
        assert "decision_counts" in parsed
        assert "top_checks" in parsed
        assert parsed["total_decisions"] >= 1

    def test_report_no_anonymize_shows_raw_owner_ids(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_mixed_chain(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--no-anonymize",
            ],
        )
        assert result.exit_code == 0, result.output
        # ``alice`` had two block decisions in the window, so the raw
        # owner string must appear in the top-blocked-owners section.
        assert "human:alice" in result.output

    def test_report_anonymize_requires_salt(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_mixed_chain(log_path, secret)

        runner = CliRunner()
        # Use isolated_filesystem to ensure no SIGNET_ANONYMIZE_SALT in env
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
            ],
            env={"SIGNET_ANONYMIZE_SALT": ""},
        )
        assert result.exit_code != 0
        assert "anonymize-salt" in result.output.lower()


# ---------------------------------------------------------------------------
# v0.1.7 P0/HIGH/MED CLI fixes
# ---------------------------------------------------------------------------


class TestDoctorSelfDownExitCode:
    """v0.1.7 C1: ``signet doctor --self <down>`` must exit non-zero
    when the proxy is unreachable. The previous version had a stray
    ``return`` in the /health except branch that skipped the final
    ``sys.exit(1 if failed else 0)``.
    """

    def test_doctor_self_unreachable_exits_1(self) -> None:
        runner = CliRunner()
        # Deliberately unroutable port -- /health probe will fail with
        # a connection-refused error.
        result = runner.invoke(main, ["doctor", "--self", "http://127.0.0.1:1/"])
        assert result.exit_code == 1, result.output
        assert "/health" in result.output
        assert "unreachable" in result.output.lower()


class TestInitPartialWriteSkip:
    """v0.1.7 C2: ``signet init`` does partial-write-skip-existing.
    Operators who delete just ``pipeline.py`` (the most common
    re-init workflow) get exactly that file scaffolded back without
    losing edits to ``client_example.py`` / ``.env.example``.
    """

    def test_init_skips_existing_client_and_env(self, tmp_path: Path) -> None:
        client_path = tmp_path / "client_example.py"
        env_path = tmp_path / ".env.example"
        client_path.write_text("# user-edited client", encoding="utf-8")
        env_path.write_text("# user-edited env\nKEY=value\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0, result.output
        # Both pre-existing files are reported as skipped.
        assert "skipped (already exists)" in result.output
        assert "client_example.py" in result.output
        assert ".env.example" in result.output
        # The originals are preserved.
        assert client_path.read_text(encoding="utf-8") == "# user-edited client"
        assert env_path.read_text(encoding="utf-8") == "# user-edited env\nKEY=value\n"
        # And the missing pipeline.py was scaffolded.
        assert (tmp_path / "pipeline.py").exists()
        assert "from signet.checks import" in (
            tmp_path / "pipeline.py"
        ).read_text(encoding="utf-8")

    def test_init_refuses_when_every_file_exists(self, tmp_path: Path) -> None:
        # All four scaffolded files pre-exist.
        for name in ("pipeline.py", ".env.example", "client_example.py", ".gitignore"):
            (tmp_path / name).write_text("pre", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 1
        assert "refusing to overwrite" in result.output


class TestKeysGenerateEd25519PathRepr:
    """v0.1.7 C4: the keys generate-ed25519 success message renders
    paths via ``repr()`` so Windows backslashes become escaped Python
    strings (``'D:\\tmp\\priv.pem'``) that parse cleanly when copy-
    pasted as code.
    """

    def test_emits_repr_quoted_paths(self, tmp_path: Path) -> None:
        priv_path = tmp_path / "signet.key"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["keys", "generate-ed25519", "--out", str(priv_path), "--key-id", "test"],
        )
        assert result.exit_code == 0, result.output
        # The emitted code uses ``private_pem_path=<repr>`` and
        # ``public_pem_path=<repr>``. ``repr(str(Path))`` always
        # produces a Python string literal -- on POSIX that's a
        # single-quoted string with forward slashes; on Windows it's
        # a single-quoted string with doubled backslashes. Either
        # parses under ``compile()``.
        assert f"private_pem_path={str(priv_path)!r}" in result.output
        assert (
            f"public_pem_path={str(priv_path) + '.pub'!r}" in result.output
        )

        # And the snippet must compile as Python.
        import re

        snippet = re.search(
            r"Ed25519ReceiptSigner\.from_pem\(\s*private_pem_path=([^,]+),",
            result.output,
        )
        assert snippet is not None
        # ``compile()`` rejects invalid escapes only when the source
        # contains them; this is the regression we care about.
        compile(f"x = {snippet.group(1)}", "<test>", "exec")


class TestPluginsDoctor:
    """v0.1.7 P1: ``signet plugins doctor`` is the CI gate for plugin
    issues. Detects duplicate (group, name) pairs and any plugin with
    non-loaded status; exit 1 when either is non-empty.
    """

    def _plugin(self, **overrides):
        from signet.plugins.discovery import DiscoveredPlugin

        defaults = {
            "group": "signet.checks",
            "name": "example",
            "package": "pkg-a",
            "package_version": "0.1.0",
            "target": "pkg_a:Example",
            "status": "loaded",
            "abi_declared": 1,
            "abi_required": 1,
            "error": None,
            "obj": object,
        }
        defaults.update(overrides)
        return DiscoveredPlugin(**defaults)

    def test_doctor_clean_exits_0(self, monkeypatch) -> None:
        plugins = [
            self._plugin(name="alpha"),
            self._plugin(name="beta", package="pkg-b"),
        ]
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "doctor"])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_doctor_flags_duplicate_names(self, monkeypatch) -> None:
        plugins = [
            self._plugin(name="duplicate", package="pkg-a"),
            self._plugin(name="duplicate", package="pkg-b"),
        ]
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "doctor"])
        assert result.exit_code == 1
        assert "DUPLICATE PLUGIN NAMES" in result.output
        assert "duplicate" in result.output
        assert "pkg-a" in result.output and "pkg-b" in result.output

    def test_doctor_flags_failed_plugins(self, monkeypatch) -> None:
        plugins = [
            self._plugin(name="ok"),
            self._plugin(
                name="bad_abi",
                status="incompatible_abi",
                abi_declared=99,
                error="declares 99; signet wants 1",
            ),
            self._plugin(
                name="bad_load",
                status="load_error",
                error="ImportError: nope",
            ),
        ]
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "doctor"])
        assert result.exit_code == 1
        assert "NON-LOADED" in result.output
        assert "bad_abi" in result.output
        assert "bad_load" in result.output

    def test_doctor_json_output(self, monkeypatch) -> None:
        import json

        plugins = [
            self._plugin(name="dup", package="a"),
            self._plugin(name="dup", package="b"),
            self._plugin(name="ok"),
        ]
        import signet.plugins as signet_plugins

        monkeypatch.setattr(
            signet_plugins, "discover_plugins", lambda *, refresh=False: plugins
        )
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "doctor", "--json"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["ok"] is False
        assert parsed["duplicate_count"] == 1
        assert parsed["duplicates"][0]["name"] == "dup"


class TestLintErrorsAreOneLine:
    """v0.1.7 C5: lint surfaces a one-line ClickException when the
    pipeline file has a syntax or import error, instead of a full
    Python traceback.
    """

    def test_syntax_error_in_pipeline_emits_clean_error(self, tmp_path: Path) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(
            "from signet.core.pipeline import Pipeline\n"
            "pipeline = Pipeline(checks=[\n"
            "    # missing close-bracket -> SyntaxError\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        assert result.exit_code != 0
        # No Python traceback should be emitted; click handles the
        # ClickException as a one-line error prefixed with "Error:".
        assert "Traceback (most recent call last)" not in result.output
        assert "syntax error" in result.output.lower()

    def test_import_error_in_pipeline_emits_clean_error(self, tmp_path: Path) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(
            "import nonexistent_signet_test_module  # noqa: F401\n"
            "from signet.core.pipeline import Pipeline\n"
            "pipeline = Pipeline(checks=[])\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output
        # The wrapped error message includes the imported name.
        out = result.output.lower()
        assert "failed to import" in out or "no module named" in out


class TestAuditCorruptLogClickException:
    """v0.1.7 C6: every audit subcommand that walks the chain emits a
    one-line ClickException on a malformed JSONL line instead of a
    Python traceback (MalformedAuditEntry).
    """

    def _build_corrupt_log(self, log_path: Path) -> None:
        # First line is valid JSON; second line is a half-written
        # entry (the realistic post-crash truncation).
        log_path.write_text(
            "{}\n"  # parses but isn't a valid AuditEntry
            "{not valid json,\n",
            encoding="utf-8",
        )

    def test_audit_count_clean_error_on_malformed(self, tmp_path: Path) -> None:
        # We need a log with one valid AuditEntry then a bad line so
        # iter_entries() actually reaches the malformed line. Build a
        # real entry first, then append garbage.
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{not valid json,\n")

        runner = CliRunner()
        result = runner.invoke(main, ["audit", "count", str(log_path)])
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output
        assert "malformed" in result.output.lower()
        assert "line 2" in result.output

    def test_audit_tail_clean_error_on_malformed(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{not valid json,\n")

        runner = CliRunner()
        result = runner.invoke(main, ["audit", "tail", str(log_path)])
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output
        assert "malformed" in result.output.lower()

    def test_audit_show_clean_error_on_malformed(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{not valid json,\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "show",
                "00000000-0000-0000-0000-000000000000",
                "--audit-log",
                str(log_path),
            ],
        )
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output
        assert "malformed" in result.output.lower()

    def test_replay_clean_error_on_malformed(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{not valid json,\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "replay",
                "00000000-0000-0000-0000-000000000000",
                "--audit-log",
                str(log_path),
            ],
        )
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output
        assert "malformed" in result.output.lower()


class TestAuditTailFilterValidation:
    """v0.1.7 C7: ``audit tail --filter foo=bar`` raises ClickException
    on unknown fields rather than silently filtering out everything.
    """

    def test_unknown_filter_field_errors(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["audit", "tail", str(log_path), "--filter", "foo=bar"]
        )
        assert result.exit_code != 0
        assert "unknown filter field" in result.output.lower()
        assert "foo" in result.output

    def test_known_filter_fields_still_work(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="rate_limit",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="prompt_injection",
                decision=Decision.BLOCK,
                reason="bad",
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", "tail", str(log_path), "--filter", "decision=block"],
        )
        assert result.exit_code == 0, result.output
        # Only the BLOCK entry should appear.
        assert "prompt_injection" in result.output
        assert "rate_limit" not in result.output


class TestLintVersionInSuccessMessage:
    """v0.1.7: lint success message interpolates ``__version__`` so it
    no longer says ``v0.1.5`` after the version moves on.
    """

    def test_success_message_uses_current_version(self, tmp_path: Path) -> None:
        from signet import __version__

        path = tmp_path / "pipeline.py"
        path.write_text(
            "from signet.checks import (OwnerResolutionCheck, "
            "ScopeDriftCheck, ClassificationGateCheck)\n"
            "from signet.core.pipeline import Pipeline\n"
            "pipeline = Pipeline(checks=[\n"
            "    OwnerResolutionCheck(require_owner=True),\n"
            "    ClassificationGateCheck(),\n"
            "    ScopeDriftCheck(),\n"
            "])\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        assert result.exit_code == 0, result.output
        assert f"v{__version__}" in result.output
        # Stale version string is gone.
        if __version__ != "0.1.5":
            assert "v0.1.5 lint checks" not in result.output


class TestSig001SubclassDocstring:
    """v0.1.7 C3: SIG001 message clarifies the trigger is a subclass
    override, since RateLimitCheck.__init__ does not accept priority=
    as a kwarg.
    """

    _SUBCLASS_PIPELINE = """
from signet.checks import (OwnerResolutionCheck, RateLimitCheck,
    ScopeDriftCheck)
from signet.core.pipeline import Pipeline


class FastRateLimit(RateLimitCheck):
    priority = 10  # documented v0.1.4 footgun


pipeline = Pipeline(checks=[
    OwnerResolutionCheck(require_owner=True),
    FastRateLimit(capacity=60, refill_per_second=1.0),
    ScopeDriftCheck(),
])
"""

    def test_sig001_fires_on_subclass_override_with_subclass_hint(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "pipeline.py"
        path.write_text(self._SUBCLASS_PIPELINE, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["lint", str(path)])
        assert "SIG001" in result.output
        assert "priority=10" in result.output
        # The remediation now mentions subclasses, not constructor args.
        assert "subclass" in result.output.lower()


class TestAuditReportPolish:
    """v0.1.7 A5/A12 + pluralization: the audit report markdown
    renders the anonymize section conditionally, strips ``+00:00``
    from ISO timestamps, and pluralizes ``block`` correctly.
    """

    def _build_chain_with_one_block(self, log_path: Path, secret: bytes) -> None:
        import time

        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        now_ns = time.time_ns()
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="prompt_injection",
                decision=Decision.BLOCK,
                reason="blocked",
                ts_ns=now_ns - 60 * 1_000_000_000,
            )
        )

    def test_no_anonymize_header_drops_anonymized_label(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain_with_one_block(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--no-anonymize",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "## Top blocked owners" in result.output
        assert "(anonymized)" not in result.output

    def test_anonymize_header_keeps_anonymized_label(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain_with_one_block(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--anonymize-salt",
                "test-salt",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "## Top blocked owners (anonymized)" in result.output

    def test_range_header_strips_double_utc_tag(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain_with_one_block(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--no-anonymize",
            ],
        )
        assert result.exit_code == 0, result.output
        # The "+00:00 UTC" double-tag must be gone.
        assert "+00:00 UTC" not in result.output
        # The single UTC label remains.
        assert " UTC " in result.output

    def test_blocks_pluralization(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        # Exactly one block by alice -> "1 block" (no s).
        self._build_chain_with_one_block(log_path, secret)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "1h",
                "--no-anonymize",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "1 block" in result.output
        # Defensively assert no "1 blocks".
        assert "1 blocks" not in result.output


class TestAuditCompactForce:
    """v0.1.7 A4: ``signet audit compact --force`` plumbs through to
    ``compact_audit_log(force=True)`` so an existing archive at
    ``--output`` can be intentionally overwritten.
    """

    def _build_chain(self, log_path: Path, secret: bytes, n: int):
        from datetime import UTC, datetime

        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        appended = []
        base_ts = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1e9)
        for i in range(n):
            entry = AuditEntry(
                owner=Owner.human(f"u{i}"),
                check_name="owner_resolution",
                decision=Decision.ALLOW,
                reason="ok",
                ts_ns=base_ts + i * 1_000_000_000,
            )
            appended.append(chain.append(entry))
        return appended

    def test_compact_refuses_when_archive_exists_without_force(
        self, tmp_path: Path
    ) -> None:
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain(log_path, secret, 3)
        archive = tmp_path / "archive.bin"
        # Pre-create the archive file so the compactor's
        # FileExistsError fires.
        archive.write_bytes(b"existing")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                "2030-01-01T00:00:00Z",
                "--output",
                str(archive),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
            ],
        )
        assert result.exit_code != 0
        assert "refusing to overwrite" in result.output.lower()
        # Original bytes must be untouched.
        assert archive.read_bytes() == b"existing"

    def test_compact_force_overwrites_existing_archive(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        entries = self._build_chain(log_path, secret, 5)
        archive = tmp_path / "archive.bin"
        archive.write_bytes(b"existing")

        cutoff_ts_ns = entries[3].ts_ns
        cutoff_iso = (
            datetime.fromtimestamp(cutoff_ts_ns / 1e9, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                cutoff_iso,
                "--output",
                str(archive),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
                "--force",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "compaction complete" in result.output
        # And the archive on disk is no longer the placeholder.
        assert archive.read_bytes() != b"existing"


class TestAuditVerifySummarizeCascades:
    """v0.1.7 A11: ``signet audit verify --summarize-cascades`` plumbs
    through to ChainVerifier(compact_breaks=True).
    """

    def test_summarize_cascades_collapses_link_breaks(self, tmp_path: Path) -> None:
        # Build a chain of N entries, then surgically tamper the FIRST
        # entry's stored ``hmac`` field. The next entry's ``prev_hmac``
        # is unchanged on disk but no longer matches the (tampered)
        # entry-1 hmac, so the verifier emits a link_mismatch on
        # entry 2. Each later entry inherits the now-broken
        # prev_hmac comparison through the same mechanism, so
        # entries 3..N also produce link_mismatch breaks. That is
        # the cascade that ``--summarize-cascades`` collapses.
        import json as _json

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        for i in range(6):
            chain.append(
                AuditEntry(
                    owner=Owner.human(f"u{i}"),
                    check_name="owner_resolution",
                    decision=Decision.ALLOW,
                    reason="ok",
                )
            )

        lines = log_path.read_text(encoding="utf-8").splitlines()
        first = _json.loads(lines[0])
        # Flip one hex character in the stored hmac.
        original = first["hmac"]
        flipped_char = "0" if original[0] != "0" else "1"
        first["hmac"] = flipped_char + original[1:]
        # Re-serialize with the same canonical form (sort_keys, no
        # whitespace) so other fields stay identical.
        lines[0] = _json.dumps(first, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        runner = CliRunner()
        baseline = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
            ],
        )
        assert baseline.exit_code == 2
        baseline_break_count = baseline.output.count("link_mismatch")
        # The cascade is real — at least the second entry's link is
        # broken by the tamper.
        assert baseline_break_count >= 1

        with_flag = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--summarize-cascades",
            ],
        )
        assert with_flag.exit_code == 2
        out_lower = with_flag.output.lower()
        # When more than one downstream entry cascades, the flag
        # introduces a CASCADE_SUPPRESSED line. With only one
        # downstream link_mismatch the verifier may still emit it
        # individually; either way, the summarized output has at
        # most as many link_mismatch lines as the baseline.
        if baseline_break_count >= 2:
            assert "cascade_suppressed" in out_lower
        assert (
            with_flag.output.count("link_mismatch")
            <= baseline_break_count
        )


class TestProbeCorpusBase32:
    """v0.1.7: the base32_encoded probe is now a real round-trippable
    encoding of ``ignore previous instructions``.
    """

    def test_base32_decodes_to_expected_text(self) -> None:
        import base64

        from signet.cli_helpers.probe_injection_corpus import (
            PROMPT_INJECTION_PROBE_CORPUS,
        )

        probe = next(
            p for p in PROMPT_INJECTION_PROBE_CORPUS if p.name == "base32_encoded"
        )
        # Strip the "Decode: " prefix.
        encoded = probe.payload.split("Decode:", 1)[1].strip()
        decoded = base64.b32decode(encoded).decode("ascii")
        assert "ignore previous instructions" in decoded.lower()

    def test_other_decoded_corpus_entries_round_trip(self) -> None:
        # Sanity-check that the other decoder probes still decode to
        # the canonical phrase. Catches similar regressions in
        # base64/hex/rot13 if anyone edits the corpus carelessly.
        import base64
        import codecs

        from signet.cli_helpers.probe_injection_corpus import (
            PROMPT_INJECTION_PROBE_CORPUS,
        )

        by_name = {p.name: p for p in PROMPT_INJECTION_PROBE_CORPUS}

        b64 = by_name["base64_encoded"].payload.split(":", 1)[1].strip()
        assert (
            "ignore previous instructions"
            in base64.b64decode(b64).decode("ascii").lower()
        )

        hex_payload = by_name["hex_encoded"].payload.split(":", 1)[1].strip()
        assert (
            "ignore previous instructions"
            in bytes.fromhex(hex_payload).decode("ascii").lower()
        )

        rot13_payload = by_name["rot13_encoded"].payload.split(":", 1)[1].strip()
        assert (
            "ignore previous instructions"
            in codecs.decode(rot13_payload, "rot_13").lower()
        )


# ---------------------------------------------------------------------------
# v0.1.7 P2 CLI polish
# ---------------------------------------------------------------------------


class TestPluginsGroupHelp:
    """C8: ``signet plugins --help`` describes the entry-point groups,
    the four reported statuses, and the ``list`` / ``doctor`` flow.
    """

    def test_help_lists_entry_point_groups(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "--help"])
        assert result.exit_code == 0, result.output
        for token in ("signet.checks", "signet.adapters", "signet.anchors"):
            assert token in result.output, (
                f"plugins help missing {token!r}: {result.output}"
            )

    def test_help_lists_four_statuses(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "--help"])
        assert result.exit_code == 0, result.output
        for status in ("loaded", "incompatible_abi", "load_error", "duplicate_name"):
            assert status in result.output, (
                f"plugins help missing status {status!r}: {result.output}"
            )

    def test_help_mentions_list_and_doctor(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "--help"])
        assert result.exit_code == 0, result.output
        assert "plugins list" in result.output
        assert "plugins doctor" in result.output


class TestKeysGenerateEd25519Sidecar:
    """C9: when ``--key-id`` is supplied, ``keys generate-ed25519`` writes
    a sidecar ``<out>.meta.json`` so the binding survives terminal close.
    """

    def test_sidecar_written_when_key_id_supplied(self, tmp_path: Path) -> None:
        import json as _json

        runner = CliRunner()
        priv_path = tmp_path / "signet.key"
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(priv_path),
                "--key-id",
                "operator-2026q2",
            ],
        )
        assert result.exit_code == 0, result.output
        meta_path = tmp_path / "signet.key.meta.json"
        assert meta_path.exists(), "sidecar meta JSON was not written"
        meta = _json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["key_id"] == "operator-2026q2"
        assert meta.get("generated_at")
        assert meta.get("signet_version")
        # Help text must advertise the sidecar so operators can rely on it.
        help_result = runner.invoke(
            main, ["keys", "generate-ed25519", "--help"]
        )
        assert ".meta.json" in help_result.output

    def test_no_sidecar_when_key_id_omitted(self, tmp_path: Path) -> None:
        runner = CliRunner()
        priv_path = tmp_path / "signet.key"
        result = runner.invoke(
            main,
            ["keys", "generate-ed25519", "--out", str(priv_path)],
        )
        assert result.exit_code == 0, result.output
        meta_path = tmp_path / "signet.key.meta.json"
        assert not meta_path.exists(), (
            "sidecar should only land when --key-id is supplied"
        )


class TestInitHelpDescribesScaffold:
    """C10: ``signet init --help`` enumerates the four scaffolded files,
    explains the per-file overwrite policy, and gives the post-init
    checklist.
    """

    def test_help_lists_four_scaffolded_files(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0, result.output
        for fname in (
            "pipeline.py",
            "client_example.py",
            ".env.example",
            ".gitignore",
        ):
            assert fname in result.output, (
                f"init help missing {fname!r}: {result.output}"
            )

    def test_help_mentions_skip_if_exists_policy(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0, result.output
        # The help text should communicate that pre-existing files are
        # skipped rather than overwritten.
        out_lower = result.output.lower()
        assert "already exist" in out_lower or "skipped" in out_lower

    def test_help_includes_post_init_serve_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0, result.output
        # The post-init checklist must point at signet serve --dev.
        assert "signet serve" in result.output
        assert "--dev" in result.output


class TestAuditVerifyEmptyChain:
    """A15: ``signet audit verify`` on an empty chain prints
    ``OK: 0 entries (chain is empty)`` rather than the cosmetic
    ``(last hmac=)`` empty parenthesis.
    """

    def test_empty_chain_omits_empty_parens(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("", encoding="utf-8")
        secret = b"x" * 32

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--key-id",
                "k1",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "OK: 0 entries" in result.output
        assert "chain is empty" in result.output
        # The dangling empty parenthesis must not appear.
        assert "(last hmac=)" not in result.output
        assert "last hmac=" not in result.output


class TestParseDurationExtended:
    """A16: ``_parse_duration`` accepts m / h / d / w suffixes and a
    subset of ISO 8601 durations.
    """

    def test_minutes_suffix(self) -> None:
        from datetime import timedelta

        from signet.cli import _parse_duration

        assert _parse_duration("30m") == timedelta(minutes=30)

    def test_weeks_suffix(self) -> None:
        from datetime import timedelta

        from signet.cli import _parse_duration

        assert _parse_duration("2w") == timedelta(weeks=2)

    def test_existing_hours_and_days_still_work(self) -> None:
        from datetime import timedelta

        from signet.cli import _parse_duration

        assert _parse_duration("24h") == timedelta(hours=24)
        assert _parse_duration("7d") == timedelta(days=7)

    def test_iso8601_pt_form(self) -> None:
        from datetime import timedelta

        from signet.cli import _parse_duration

        assert _parse_duration("PT1H30M") == timedelta(hours=1, minutes=30)
        assert _parse_duration("PT90M") == timedelta(minutes=90)

    def test_iso8601_pnd_and_pnw(self) -> None:
        from datetime import timedelta

        from signet.cli import _parse_duration

        assert _parse_duration("P1D") == timedelta(days=1)
        assert _parse_duration("P1W") == timedelta(weeks=1)

    def test_iso8601_year_or_month_rejected(self) -> None:
        import click as _click
        import pytest as _pytest

        from signet.cli import _parse_duration

        # Years and months are rejected because their length depends
        # on calendar position.
        for spec in ("P1Y", "P1M"):
            with _pytest.raises(_click.ClickException):
                _parse_duration(spec)

    def test_garbage_rejected(self) -> None:
        import click as _click
        import pytest as _pytest

        from signet.cli import _parse_duration

        for spec in ("", "abc", "30x", "P", "PT", "-1h"):
            with _pytest.raises(_click.ClickException):
                _parse_duration(spec)

    def test_help_enumerates_accepted_formats(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "report", "--help"])
        assert result.exit_code == 0, result.output
        # The new help text enumerates m / h / d / w and ISO 8601.
        for token in ("minutes", "hours", "days", "weeks", "ISO 8601"):
            assert token in result.output, (
                f"audit report --since help missing {token!r}: {result.output}"
            )

    def test_audit_report_accepts_minutes_window(self, tmp_path: Path) -> None:
        # End-to-end: passing --since 30m must not raise; the report
        # renders with an empty chain (zero decisions) but exit 0.
        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="owner_resolution",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "30m",
                "--anonymize-salt",
                "test-salt",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "# signet audit report" in result.output


class TestV018ConfidenceHuntFixes:
    """Regression tests for the v0.1.7 -> v0.1.7.1 confidence-hunt
    findings (A9, A13/F2, F1, F3). Each test name carries the finding
    ID so future hunters can correlate the regression back to the
    original report.
    """

    def _build_chain(
        self,
        log_path: Path,
        secret: bytes,
        n: int = 5,
        *,
        owner_human: str = "alice",
        decision: Decision = Decision.BLOCK,
    ):
        from datetime import UTC, datetime

        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        base_ts = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1e9)
        appended = []
        for i in range(n):
            entry = AuditEntry(
                owner=Owner.human(owner_human),
                check_name="owner_resolution",
                decision=decision,
                reason="ok",
                ts_ns=base_ts + i * 1_000_000_000,
            )
            appended.append(chain.append(entry))
        return appended

    # ------------------------------------------------------------------
    # A9: --anonymize slug must be 16 hex characters (64 bits)
    # ------------------------------------------------------------------
    def test_a9_anonymize_slug_16_hex(self, tmp_path: Path) -> None:
        """v0.1.7 charter: anonymize slug is 16 hex chars (64 bits) for
        better resistance to rainbow-table attacks on plausible owner IDs.

        v0.1.7-rc kept ``h[:8]`` in ``_maybe_anonymize_owner`` despite
        the charter bump; this test pins the 16-hex contract so a
        future regression to 8 hex is caught at CI time.
        """
        import re

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain(log_path, secret, n=3, owner_human="alice")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "100000h",  # window large enough to include 2026-01-01
                "--anonymize",
                "--anonymize-salt",
                "foo",
            ],
        )
        assert result.exit_code == 0, result.output
        slug_match = re.search(r"owner_([0-9a-f]+)", result.output)
        assert slug_match is not None, (
            f"no owner_<hex> slug in report output:\n{result.output}"
        )
        slug_hex = slug_match.group(1)
        assert len(slug_hex) == 16, (
            f"anonymize slug is {len(slug_hex)} hex chars (expected 16, "
            f"i.e. 64 bits of entropy). v0.1.7 charter bug A9 has "
            f"regressed. Match: {slug_match.group(0)!r}"
        )

    def test_a9_anonymize_helper_returns_16_hex(self) -> None:
        """Unit-level pin on ``_maybe_anonymize_owner`` so even renderer
        refactors that bypass the markdown path can't silently revert
        the slug width.
        """
        from signet.cli import _maybe_anonymize_owner

        slug = _maybe_anonymize_owner(
            "human:alice@example.com", anonymize=True, salt="any-salt"
        )
        assert slug.startswith("owner_")
        hex_part = slug[len("owner_"):]
        assert len(hex_part) == 16
        assert all(c in "0123456789abcdef" for c in hex_part)

    # ------------------------------------------------------------------
    # A13 / F2: audit verify --json must include signet_version + verified_at
    # ------------------------------------------------------------------
    def test_a13_verify_json_includes_version_and_verified_at(
        self, tmp_path: Path
    ) -> None:
        """v0.1.7 charter: ``audit verify --json`` payload includes
        ``signet_version`` (binary identity for long-term forensics)
        and ``verified_at`` (UTC ISO 8601 stamp for "when was this
        checked"). Both came in on the ``VerificationReport`` dataclass
        in v0.1.7 but the CLI's JSON serializer didn't surface them.
        """
        import json as _json
        import re

        import signet as _signet

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain(log_path, secret, n=2, decision=Decision.ALLOW)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--key-id",
                "k1",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = _json.loads(result.output)

        assert "signet_version" in payload, (
            f"--json missing signet_version: {payload!r}"
        )
        assert payload["signet_version"] == _signet.__version__

        assert "verified_at" in payload, (
            f"--json missing verified_at: {payload!r}"
        )
        # Loose ISO 8601 UTC pattern: 2026-05-09T17:42:31.123456+00:00
        # (datetime.now(UTC).isoformat() always emits +00:00, not Z).
        assert re.match(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?\+00:00$",
            payload["verified_at"],
        ), f"verified_at not ISO 8601 UTC: {payload['verified_at']!r}"

    def test_a13_verify_json_includes_fields_on_broken_chain(
        self, tmp_path: Path
    ) -> None:
        """The same two fields must appear on the failure path too --
        a stored verification of a broken chain is exactly where
        long-term forensics needs the binary version and timestamp.
        """
        import json as _json

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        self._build_chain(
            log_path, secret, n=2, owner_human="alice", decision=Decision.ALLOW
        )
        # Tamper.
        text = log_path.read_text(encoding="utf-8")
        log_path.write_text(text.replace("alice", "mallory"), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "verify",
                str(log_path),
                "--hmac-secret",
                secret.hex(),
                "--key-id",
                "k1",
                "--json",
            ],
        )
        assert result.exit_code == 2, result.output
        payload = _json.loads(result.output)
        assert "signet_version" in payload
        assert "verified_at" in payload
        assert payload["ok"] is False

    # ------------------------------------------------------------------
    # F1: audit compact --force surfaces ValueError as ClickException
    # ------------------------------------------------------------------
    def test_f1_compact_stacked_marker_no_traceback(
        self, tmp_path: Path
    ) -> None:
        """v0.1.7 F1: when the compactor refuses to stack a second
        compaction over a previous marker, the CLI surfaces it as a
        ClickException (Error: ...) instead of dumping a raw Python
        traceback. --force does not silence the marker check (that's a
        data-integrity guard, not the file-overwrite refusal).
        """
        from datetime import UTC, datetime, timedelta

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        keyring = KeyRing(active=Key(key_id="k1", secret=secret))
        chain = HmacChain(JsonlBackend(log_path), keyring)
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(10):
            chain.append(
                AuditEntry(
                    owner=Owner.human(f"u{i}"),
                    check_name="owner_resolution",
                    decision=Decision.ALLOW,
                    reason="ok",
                    ts_ns=base_ns + i * 1_000_000_000,
                )
            )

        runner = CliRunner()
        # First compaction succeeds.
        archive1 = tmp_path / "archive-1.bin"
        first_cutoff = (base_dt + timedelta(seconds=5)).isoformat().replace(
            "+00:00", "Z"
        )
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                first_cutoff,
                "--output",
                str(archive1),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
            ],
        )
        assert result.exit_code == 0, result.output

        # Append entries past the marker so the second compaction has
        # something eligible plus the marker in-window.
        keyring2 = KeyRing(active=Key(key_id="k1", secret=secret))
        chain2 = HmacChain(JsonlBackend(log_path), keyring2)
        for i in range(3):
            chain2.append(
                AuditEntry(
                    owner=Owner.human(f"post-{i}"),
                    check_name="owner_resolution",
                    decision=Decision.ALLOW,
                    reason="ok",
                )
            )

        # Second compaction with --force AND a far-future cutoff that
        # sweeps in the existing marker. compactor must refuse with
        # ValueError("previous compaction marker ...").
        archive2 = tmp_path / "archive-2.bin"
        result2 = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                "2099-01-01T00:00:00Z",
                "--output",
                str(archive2),
                "--hmac-secret",
                secret.hex(),
                "--quiesce-confirm",
                "--force",
            ],
        )
        assert result2.exit_code != 0, result2.output
        # Click's ClickException renders as "Error: <msg>" without
        # leaking a Python traceback into stdout/stderr capture.
        assert "Traceback" not in result2.output
        assert "previous compaction marker" in result2.output
        # The error must be surfaced via click's Error: prefix so the
        # operator sees actionable text, not an internal exception type.
        assert "Error:" in result2.output

    # ------------------------------------------------------------------
    # F3: signet init scaffold must include PromptInjectionCheck
    # ------------------------------------------------------------------
    def test_f3_scaffold_includes_prompt_injection_check(
        self, tmp_path: Path
    ) -> None:
        """v0.1.7 F3: the init scaffold's pipeline.py must include
        ``PromptInjectionCheck`` so ``signet doctor --probe-injection``
        run against a fresh ``signet init`` scaffold returns refusals,
        not 9/9 LEAKED. The check is the only one that gates the probe
        corpus; an operator who follows the README to the letter
        should not have to learn about it the hard way.
        """
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 0, result.output

        pipeline_text = (tmp_path / "pipeline.py").read_text(encoding="utf-8")
        assert "PromptInjectionCheck" in pipeline_text, (
            "scaffolded pipeline.py does not register PromptInjectionCheck; "
            "doctor --probe-injection will report 9/9 LEAKED against a "
            "fresh init. See v0.1.7 F3."
        )

        # Load the scaffolded pipeline and assert the check is actually
        # in pipeline.checks (the source text check above is necessary
        # but not sufficient -- a stray import without registration
        # would still pass that text-match).
        from signet.checks import PromptInjectionCheck
        from signet.cli import _load_pipeline_from_path

        pipeline = _load_pipeline_from_path(tmp_path / "pipeline.py")
        assert any(
            isinstance(c, PromptInjectionCheck) for c in pipeline.checks
        ), (
            "scaffolded pipeline imports PromptInjectionCheck but does "
            "not register it in the Pipeline(checks=[...]) list."
        )
