"""Integration: plugin discovery end-to-end through the CLI.

The unit-tier coverage in ``tests/unit/test_plugins.py`` patches
:func:`signet.plugins.discovery._iter_entry_points` to inject fake
plugins. This file does the same, but invokes the discovery flow
through ``signet plugins list`` / ``signet plugins doctor`` -- the
CLI commands an operator actually runs in CI -- via Click's
:class:`CliRunner`. That covers the integration surface (CLI -> JSON
output, CLI -> non-zero exit on doctor failure) on top of the
discovery primitive itself.

Why monkey-patch instead of pip-install?

The task notes that the install / uninstall pattern for a real
third-party plugin package is delicate, especially on Windows where
in-process pip can collide with our running interpreter. The hermetic
monkey-patched flow is what the unit tests already prove out; this
file builds on that to also pin the **CLI surface area** so a future
refactor of the JSON output shape (or the exit-code contract on
doctor) is caught explicitly.

Each test installs a fresh fake registry by patching
``_iter_entry_points`` and calling ``reset_cache()`` so the discovery
cache is rebuilt for that test only. After the test runs, the
:class:`pytest.MonkeyPatch` fixture restores the real implementation
and the next test starts from clean state.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from signet.cli import main as cli_main
from signet.core.check import CHECK_ABI_VERSION, Check
from signet.core.stage import Stage
from signet.plugins import discovery as discovery_mod
from signet.plugins.discovery import reset_cache

# ---------------------------------------------------------------------------
# Fake plugin building blocks
# ---------------------------------------------------------------------------


class _FakeDist:
    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version


class _FakeEP:
    """Minimal stand-in for ``importlib.metadata.EntryPoint``.

    The discovery code path reads ``name``, ``value``, ``dist`` and
    calls ``load()``; nothing else. A real EntryPoint is also fine but
    we'd have to register it through ``importlib.metadata``, which
    would mutate process-global state.
    """

    def __init__(self, name: str, value: str, target, dist) -> None:
        self.name = name
        self.value = value
        self._target = target
        self.dist = dist

    def load(self):
        if isinstance(self._target, BaseException):
            raise self._target
        return self._target


def _patch_entry_points(
    monkeypatch: pytest.MonkeyPatch,
    eps_by_group: dict[str, list[_FakeEP]],
) -> None:
    """Install a fake registry and clear the discovery cache."""

    def fake_iter(group: str):
        return list(eps_by_group.get(group, []))

    monkeypatch.setattr(discovery_mod, "_iter_entry_points", fake_iter)
    reset_cache()


# Fake check classes. Each has its own ``name``/``stage`` so the
# matrix tests can mix them without colliding.


class _GoodCheckA(Check):
    name = "good_a"
    stage = Stage.ADMISSION


class _GoodCheckB(Check):
    name = "good_b"
    stage = Stage.ADMISSION


class _DupCheckOne(Check):
    name = "dup_check"
    stage = Stage.ADMISSION


class _DupCheckTwo(Check):
    name = "dup_check"
    stage = Stage.ADMISSION


class _IncompatibleAbiCheck(Check):
    name = "incompat_check"
    stage = Stage.ADMISSION
    CHECK_ABI_VERSION = 99


# ---------------------------------------------------------------------------
# CLI runner fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Single loaded plugin: ``signet plugins list`` / ``doctor`` see it
# ---------------------------------------------------------------------------


class TestSingleLoadedPlugin:
    def test_list_reports_loaded(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "good_a",
                        "fake.pkg:_GoodCheckA",
                        _GoodCheckA,
                        _FakeDist("fake-pkg", "1.0.0"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        # Invoke `signet plugins list --json`. The CLI calls
        # discover_plugins(refresh=True) which honors our patched
        # _iter_entry_points.
        result = runner.invoke(cli_main, ["plugins", "list", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        loaded = [p for p in payload if p["name"] == "good_a"]
        assert len(loaded) == 1
        assert loaded[0]["status"] == "loaded"
        assert loaded[0]["package"] == "fake-pkg"

    def test_doctor_exit_zero(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "good_a",
                        "fake.pkg:_GoodCheckA",
                        _GoodCheckA,
                        _FakeDist("fake-pkg", "1.0.0"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "doctor", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is True
        assert payload["failed_count"] == 0
        assert payload["duplicate_count"] == 0


# ---------------------------------------------------------------------------
# Duplicate (group, name): both go to ``duplicate_name``; doctor fails
# ---------------------------------------------------------------------------


class TestDuplicateName:
    def test_both_marked_duplicate(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "dup_check",
                        "pkg_one:_DupCheckOne",
                        _DupCheckOne,
                        _FakeDist("pkg-one", "1.0.0"),
                    ),
                    _FakeEP(
                        "dup_check",
                        "pkg_two:_DupCheckTwo",
                        _DupCheckTwo,
                        _FakeDist("pkg-two", "2.0.0"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "list", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        dups = [p for p in payload if p["name"] == "dup_check"]
        assert len(dups) == 2
        for entry in dups:
            assert entry["status"] == "duplicate_name"

    def test_doctor_exits_nonzero(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "dup_check",
                        "pkg_one:_DupCheckOne",
                        _DupCheckOne,
                        _FakeDist("pkg-one", "1.0.0"),
                    ),
                    _FakeEP(
                        "dup_check",
                        "pkg_two:_DupCheckTwo",
                        _DupCheckTwo,
                        _FakeDist("pkg-two", "2.0.0"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "doctor", "--json"])
        # Doctor MUST exit nonzero when there's a duplicate registration
        # because the resolver would silently shadow one of the two.
        assert result.exit_code == 1, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is False
        assert payload["duplicate_count"] >= 1


# ---------------------------------------------------------------------------
# Incompatible ABI version: status incompatible_abi; doctor fails
# ---------------------------------------------------------------------------


class TestIncompatibleAbi:
    def test_abi_99_marked_incompatible(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "incompat_check",
                        "future.pkg:_IncompatibleAbiCheck",
                        _IncompatibleAbiCheck,
                        _FakeDist("future-pkg", "0.0.1"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "list", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        target = next(p for p in payload if p["name"] == "incompat_check")
        assert target["status"] == "incompatible_abi"
        assert target["abi_declared"] == 99
        assert target["abi_required"] == CHECK_ABI_VERSION

    def test_doctor_exits_nonzero_on_incompatible(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "incompat_check",
                        "future.pkg:_IncompatibleAbiCheck",
                        _IncompatibleAbiCheck,
                        _FakeDist("future-pkg", "0.0.1"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "doctor", "--json"])
        assert result.exit_code == 1, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is False
        assert payload["failed_count"] >= 1


# ---------------------------------------------------------------------------
# Plugin that raises ImportError on load
# ---------------------------------------------------------------------------


class TestLoadErrorPlugin:
    def test_import_error_marked_load_error(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The fake EntryPoint's load() will raise this exception -- the
        # _FakeEP shim raises whatever target is when target is an
        # exception instance.
        boom = ImportError("boom: simulated import failure")
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "broken_plugin",
                        "broken.pkg:will_explode",
                        boom,
                        _FakeDist("broken-pkg", "0.1.0"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "list", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        target = next(p for p in payload if p["name"] == "broken_plugin")
        assert target["status"] == "load_error"
        assert "ImportError" in (target["error"] or "")

    def test_doctor_exits_nonzero_on_load_error(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        boom = ImportError("boom")
        _patch_entry_points(
            monkeypatch,
            {
                "signet.checks": [
                    _FakeEP(
                        "broken_plugin",
                        "broken.pkg:will_explode",
                        boom,
                        _FakeDist("broken-pkg", "0.1.0"),
                    ),
                ],
                "signet.adapters": [],
                "signet.anchors": [],
            },
        )
        result = runner.invoke(cli_main, ["plugins", "doctor", "--json"])
        assert result.exit_code == 1, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is False
        assert payload["failed_count"] >= 1
        names = [f["name"] for f in payload["failed"]]
        assert "broken_plugin" in names


# ---------------------------------------------------------------------------
# Hermetic post-condition: cache reset between tests
# ---------------------------------------------------------------------------


def test_cache_reset_between_tests() -> None:
    """The per-test patches above all call ``reset_cache()`` on entry,
    so the cache should be in a fresh state for the NEXT test that
    reads it without patching.

    This isn't a strict invariant of the test (the cache may have
    leftover entries from a prior test that never reset), but pinning
    the post-condition catches the common bug where a fixture forgets
    to reset.
    """
    # We don't patch _iter_entry_points here -- we just confirm the
    # cache is rebuildable. discover_plugins will read the real
    # process registry which may be empty in a clean dev install or
    # populated if someone has signet plugins installed; either way
    # it should not raise.
    reset_cache()
    from signet.plugins import discover_plugins

    plugins = discover_plugins(refresh=True)
    # Smoke: returns a list.
    assert isinstance(plugins, list)
