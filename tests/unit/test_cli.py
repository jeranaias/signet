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

    def test_replay_still_works_with_deprecation_warning(self, tmp_path: Path) -> None:
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
        # Output should still print the entry...
        assert appended.entry_id in result.output
        # ...and include the deprecation warning
        assert "deprecated" in result.output.lower()


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
