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
        (tmp_path / "pipeline.py").write_text("# pre-existing", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["init", str(tmp_path)])
        assert result.exit_code == 1
        assert "refusing to overwrite" in result.output

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
