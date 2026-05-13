"""Round 17 CLI/audit-surface hunt closures — F-R17-1 / F-R17-2.

Round 17 also probed the R16 CLI closures (audit surfaces, plugin
discovery sanitization) and surfaced two findings outside the SSE /
walker class covered in ``test_round17_hunt.py``:

MED:

- ``F-R17-1 keys generate-ed25519 silent private-key destruction``:
  ``signet keys generate-ed25519 --out CON --force`` silently routed
  the PEM-encoded private key bytes to the Win32 console / null
  device. The matching ``.pub`` file persisted because the ``.pub``
  suffix breaks the device-name match. Operators who shared the
  orphaned public key with verifiers could not produce matching
  signatures. The R15 closure already had
  ``_reject_windows_reserved_device_name`` -- it just needed to fire
  on the keys-gen output paths and on the ``audit compact --output``
  archive path for consistency.

LOW:

- ``F-R17-2 plugin discovery exception-message DoS``: R15 (F-R15-2)
  added ``_truncate_for_log`` at two ``_sanitize_for_log(repr(obj))``
  sites but missed the third site -- the load-error branch's
  ``_sanitize_for_log(exc)``. A hostile plugin whose ``ep.load()``
  raised an exception whose ``__str__`` returns 10 MB of escape bytes
  could stall discovery for tens of seconds and cache the multi-MB
  rendered string in ``_DISCOVERED_PLUGINS_CACHE.error`` for the
  process lifetime. Post-fix the load-error branch caps via
  ``_truncate_for_log`` the same way the other two sites do, and
  the cached ``error`` field carries the same truncated form.
"""

from __future__ import annotations

import time
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from signet.cli import (
    _reject_windows_reserved_device_name,
    main,
)
from signet.plugins import discovery as plugin_discovery
from signet.plugins.discovery import (
    _LOG_TRUNCATION_MARKER,
)

# ---------------------------------------------------------------------------
# F-R17-1 — keys generate-ed25519 reserved device-name guard
# ---------------------------------------------------------------------------


class TestF_R17_1_KeysGenerateReservedDeviceName:
    """``keys generate-ed25519`` rejects Windows reserved device-name
    output paths at parse time."""

    @pytest.mark.parametrize(
        "name",
        [
            "CON",
            "NUL",
            "PRN",
            "AUX",
            "COM1",
            "LPT1",
            # R15 trailing-whitespace variants must also fire here.
            "CON ",
            "CON.",
            "CON\t",
            "CON  ",
            "CON. ",
            "LPT1 ",
            # Lower / mixed case is upper-cased before lookup.
            "con",
            "Con",
            "lpt1 ",
        ],
    )
    def test_reject_helper_kind_out(self, name: str) -> None:
        """The helper raises with the ``--out`` ``kind`` substring so
        the operator-facing error names the offending CLI option."""
        with pytest.raises(click.exceptions.ClickException) as excinfo:
            _reject_windows_reserved_device_name(Path(name), kind="--out")
        message = str(excinfo.value.message)
        assert "Windows reserved device name" in message
        assert "--out" in message

    def test_reject_helper_kind_public_out(self) -> None:
        with pytest.raises(click.exceptions.ClickException) as excinfo:
            _reject_windows_reserved_device_name(Path("CON"), kind="--public-out")
        assert "--public-out" in str(excinfo.value.message)

    def test_reject_helper_default_kind_preserved(self) -> None:
        """The default ``kind`` argument keeps the original "audit log
        path" wording so existing callsites still produce the same
        operator-facing message."""
        with pytest.raises(click.exceptions.ClickException) as excinfo:
            _reject_windows_reserved_device_name(Path("CON"))
        assert "audit log path" in str(excinfo.value.message)
        assert "Windows reserved device name" in str(excinfo.value.message)

    @pytest.mark.parametrize(
        "name",
        ["CON", "NUL", "CON ", "CON.", "LPT1", "com1", "Aux"],
    )
    def test_keys_generate_rejects_reserved_out(self, tmp_path: Path, name: str) -> None:
        """End-to-end via click: every Win32-routed reserved-name
        basename passed to ``--out`` must be refused with a
        ClickException, not a silent write to the device."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "keys",
                    "generate-ed25519",
                    "--out",
                    name,
                    "--force",
                ],
            )
            assert result.exit_code != 0
            assert "Windows reserved device name" in result.output
            # Output must stay terminal-safe (no raw escape bytes).
            assert "\x1b" not in result.output
            # The matching ``.pub`` file must not be created -- the
            # guard fires before any write happens, so neither private
            # nor public key bytes land on disk.
            assert not Path(name + ".pub").exists()

    def test_keys_generate_with_extension_out(self) -> None:
        """Reserved-name + extension still routes on Win32 (e.g.
        ``CON.txt``) and is refused."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "keys",
                    "generate-ed25519",
                    "--out",
                    "CON.txt",
                    "--force",
                ],
            )
            assert result.exit_code != 0
            assert "Windows reserved device name" in result.output

    def test_keys_generate_rejects_reserved_public_out(self, tmp_path: Path) -> None:
        """``--public-out CON`` must be refused even when ``--out`` is a
        normal path -- a hostile env-var only routes the public key to
        the device, but the private key still lands on disk, so a
        verifier configured against the orphaned (would-be) public-key
        file cannot accept signatures from the actual private key.
        Same guard class either way."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(tmp_path / "priv.pem"),
                "--public-out",
                "NUL.pub",
                "--force",
            ],
        )
        assert result.exit_code != 0
        assert "Windows reserved device name" in result.output

    def test_keys_generate_normal_path_still_works(self, tmp_path: Path) -> None:
        """The guard must not over-reach onto normal output paths.
        Smoke test that a regular ``--out`` still produces a keypair.

        Skipped silently if ``cryptography`` is not importable so the
        test stays useful in the minimal-dep CI matrix.
        """
        try:
            import cryptography  # noqa: F401
        except ImportError:
            pytest.skip("cryptography not installed")

        runner = CliRunner()
        out = tmp_path / "priv.pem"
        result = runner.invoke(
            main,
            [
                "keys",
                "generate-ed25519",
                "--out",
                str(out),
                "--force",
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert out.with_suffix(out.suffix + ".pub").exists()
        # Private key file is non-empty (not a wedged device handle).
        assert out.stat().st_size > 0


# ---------------------------------------------------------------------------
# F-R17-1 sweep — audit compact --output also gets the guard
# ---------------------------------------------------------------------------


class TestF_R17_1_AuditCompactOutputGuard:
    """``audit compact --output CON`` is refused at parse time even
    though ``compactor.py`` would have ``Path(output).resolve()``-ed
    around the device-routing issue. Refusing it consistently keeps
    the CLI from producing a UX foot-gun (a file named ``CON`` that
    is awkward to open / delete from Windows Explorer)."""

    def test_audit_compact_rejects_reserved_output(self, tmp_path: Path) -> None:
        # Build a placeholder live audit log so ``click.Path(exists=True)``
        # doesn't bail before our guard runs.
        live = tmp_path / "live.jsonl"
        live.write_bytes(b"")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit",
                "compact",
                "--audit-log",
                str(live),
                "--before",
                "2026-01-01T00:00:00Z",
                "--output",
                "CON",
                "--hmac-secret",
                "00" * 32,
                "--quiesce-confirm",
            ],
        )
        assert result.exit_code != 0
        assert "Windows reserved device name" in result.output


# ---------------------------------------------------------------------------
# F-R17-2 — plugin discovery load-error branch hostile exception
# ---------------------------------------------------------------------------


class TestF_R17_2_LoadErrorTruncation:
    """A plugin whose ``ep.load()`` raises an exception with a 10 MB
    ``__str__`` must NOT stall discovery, and the cached ``error``
    field must be bounded so subsequent ``plugins list`` /
    ``plugins doctor`` invocations do not re-render the multi-MB
    payload."""

    def test_hostile_exception_does_not_stall_discovery(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _HostileExc(Exception):
            def __str__(self) -> str:
                # 10 MB of bidi-laden escape bytes -- a hostile plugin
                # exception's ``__str__`` is plugin-controlled. R15's
                # truncation cap missed this site so a 10 MB ``str(exc)``
                # produced a ~54 s sanitize stall + 40 MB cached error.
                return ("safe‮evil" * 1_000_000)[:10_000_000]

        class _FakeEP:
            name = "evilplugin"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise _HostileExc("ignored -- __str__ overrides this")

        def _fake_iter(group: str) -> list[_FakeEP]:
            if group == "signet.checks":
                return [_FakeEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        t0 = time.perf_counter()
        plugins = plugin_discovery.discover_plugins(refresh=True)
        elapsed = time.perf_counter() - t0

        # Bounded wall-clock: post-fix the sanitize step sees at most
        # 1024 chars + marker, well under 100 ms on CI hardware. We
        # use 1.0 s as a generous bound that still catches any
        # regression to the 54 s pre-fix shape.
        assert elapsed < 1.0, f"discovery took {elapsed:.3f}s"

        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.status == "load_error"
        assert plugin.error is not None
        # Cached error must be bounded -- not 40 MB.
        assert _LOG_TRUNCATION_MARKER in plugin.error
        assert len(plugin.error) < 4 * 1024
        # Raw bidi codepoint is escaped, not preserved.
        assert "‮" not in plugin.error

        # Clean up the cache so we don't pollute the next test.
        plugin_discovery.reset_cache()

    def test_hostile_exception_cache_does_not_grow_on_subsequent_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Subsequent ``discover_plugins`` calls (without ``refresh=True``)
        return the cached, bounded ``error`` field -- never re-render
        the multi-MB ``str(exc)`` payload."""

        class _HostileExc(Exception):
            def __str__(self) -> str:
                return "x" * 5_000_000  # 5 MB

        class _FakeEP:
            name = "evilplugin2"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise _HostileExc()

        def _fake_iter(group: str) -> list[_FakeEP]:
            if group == "signet.checks":
                return [_FakeEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        first = plugin_discovery.discover_plugins(refresh=True)
        second = plugin_discovery.discover_plugins(refresh=False)
        # Same cached list (identity hold described in the discovery
        # docstring).
        assert first is second
        assert first[0].error is not None
        assert len(first[0].error) < 4 * 1024

        plugin_discovery.reset_cache()

    def test_doctor_output_shows_truncation_marker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``plugins doctor`` renders the truncated ``error`` field --
        an operator sees the marker rather than the raw multi-MB
        payload."""

        class _HostileExc(Exception):
            def __str__(self) -> str:
                return "x" * 5_000_000

        class _FakeEP:
            name = "evilplugin3"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise _HostileExc()

        def _fake_iter(group: str) -> list[_FakeEP]:
            if group == "signet.checks":
                return [_FakeEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "doctor"])
        # Non-zero exit because there's a failed plugin.
        assert result.exit_code != 0
        # Truncation marker must appear in the rendered output.
        assert _LOG_TRUNCATION_MARKER in result.output
        # Output is bounded in size -- not a multi-MB stderr dump.
        assert len(result.output) < 16 * 1024

        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R17-2 sweep — every _sanitize_for_log site in discovery wraps with
# _truncate_for_log
# ---------------------------------------------------------------------------


class TestF_R17_2_SanitizeForLogSiteSweep:
    """Every ``_sanitize_for_log(...)`` site in ``discovery.py`` must
    be wrapped with ``_truncate_for_log(...)``. Source-level audit so a
    future refactor cannot regress the cap on any of the plugin-
    controlled interpolation points (entry-point name, group,
    ``obj.__name__``, distribution name, exception text)."""

    def test_every_sanitize_call_is_truncation_wrapped(self) -> None:
        """Parse ``discovery.py`` via ``ast`` and walk every
        ``Call`` node whose ``func`` is the bare name
        ``_sanitize_for_log``. Each such call must take a single
        positional argument that is either a ``_truncate_for_log(...)``
        call OR one of the well-known pre-truncated names produced at
        the start of the surrounding block (``exc_str_safe`` /
        ``obj_repr_safe`` / ``declared_repr_safe``). The helper's own
        definition is skipped -- we only inspect callsites elsewhere
        in the module."""
        import ast

        source = Path(plugin_discovery.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)

        # Locate the helper's FunctionDef so we can skip walking its
        # own body. The body contains no call to itself today, but a
        # future refactor could recursively call -- and we don't want
        # to flag that defensive shape if it happens.
        helper_node: ast.FunctionDef | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_sanitize_for_log":
                helper_node = node
                break
        assert helper_node is not None, "expected to find ``def _sanitize_for_log`` in discovery.py"
        helper_lineno = helper_node.lineno
        helper_end = helper_node.end_lineno or helper_node.lineno

        _ALLOWED_NAMES = {
            "exc_str_safe",
            "obj_repr_safe",
            "declared_repr_safe",
        }
        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id == "_sanitize_for_log"):
                continue
            # Skip any call that lexically lives inside the helper's
            # own body.
            if helper_lineno <= node.lineno <= helper_end:
                continue
            if len(node.args) != 1:
                offenders.append(
                    f"discovery.py:{node.lineno}: "
                    f"_sanitize_for_log() called with "
                    f"{len(node.args)} positional args"
                )
                continue
            arg = node.args[0]
            # Allowed shape A: ``_truncate_for_log(...)`` wrapping.
            if (
                isinstance(arg, ast.Call)
                and isinstance(arg.func, ast.Name)
                and arg.func.id == "_truncate_for_log"
            ):
                continue
            # Allowed shape B: a Name reference to one of the
            # pre-truncated variables computed at the top of the
            # surrounding block.
            if isinstance(arg, ast.Name) and arg.id in _ALLOWED_NAMES:
                continue
            offenders.append(
                f"discovery.py:{node.lineno}: "
                f"_sanitize_for_log(...) missing _truncate_for_log "
                f"wrapper (arg ast: {type(arg).__name__})"
            )

        assert not offenders, "\n".join(offenders)
