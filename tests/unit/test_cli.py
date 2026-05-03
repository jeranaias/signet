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
