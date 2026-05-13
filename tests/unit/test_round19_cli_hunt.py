"""Round 19 CLI / discovery hunt closures — F-R19-1 / F-R19-2 / F-R19-3.

Round 19 surfaced three findings on the R18 CLI / discovery surface
(audit document: ``D:/tmp/signet-hunt-round19/findings/audit_cli.md``).
These are distinct from the SERVER + STREAMING findings in
``test_round19_hunt.py`` -- mirrors the R17 split into
``test_round17_hunt.py`` (SSE / walker) and
``test_round17_cli_hunt.py`` (CLI / audit surfaces).

HIGH:

- ``F-R19-1 plugin __repr__ / __str__ raises crashes discovery walk``:
  R18 added ``_truncate_for_log(repr(obj))`` to bound size, but
  ``repr(obj)`` itself can raise from a hostile metaclass / class
  ``__repr__`` or from a non-int ``CHECK_ABI_VERSION`` whose
  ``__repr__`` raises. The same shape applies to ``str(exc)`` at the
  load-error branch -- a hostile exception class can override
  ``__str__`` to raise. Either case aborts the discovery walk and
  skips every later entry point. R19 introduces ``_safe_repr`` /
  ``_safe_str`` helpers that wrap the conversion in a ``BaseException``
  catch (so hostile ``__repr__`` raising ``SystemExit`` /
  ``KeyboardInterrupt`` can't escape the guard either) and substitute
  a fixed fallback string when conversion raises.

MED:

- ``F-R19-2 plugin ep.load() raising BaseException bypasses guard``:
  ``except Exception`` does NOT catch ``BaseException`` subclasses --
  ``KeyboardInterrupt``, ``SystemExit``, ``GeneratorExit``,
  ``MemoryError`` all escape. A hostile plugin whose import-time code
  raises any of these propagates out of ``discover_plugins`` and
  crashes the entire walk. R19 widens to ``except BaseException`` and
  re-raises ``(KeyboardInterrupt, SystemExit)`` BEFORE recording so
  genuine operator Ctrl+C and process-exit semantics still propagate.

LOW:

- ``F-R19-3 signet init <reserved-device-name> raw traceback``:
  ``signet init CON`` triggered a raw ``NotADirectoryError`` traceback
  from ``Path.mkdir`` instead of the canonical ``ClickException``.
  The R17 / R18 closures had already guarded the audit-log, keys-gen,
  and audit-compact output surfaces; ``init`` was the last remaining
  reserved-name surface that produced a raw traceback. R19 calls
  ``_reject_windows_reserved_device_name`` at the top of ``init()``
  to match the other write surfaces.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import ClassVar

import click
import pytest
from click.testing import CliRunner

from signet.cli import (
    _reject_windows_reserved_device_name,
    main,
)
from signet.plugins import discovery as plugin_discovery
from signet.plugins.discovery import (
    _safe_repr,
    _safe_str,
)

# ---------------------------------------------------------------------------
# F-R19-1 — _safe_repr / _safe_str helpers
# ---------------------------------------------------------------------------


class TestF_R19_1_CliHunt_SafeReprHelper:
    """The ``_safe_repr`` helper returns a fallback string when
    ``repr(obj)`` raises any ``BaseException`` subclass. The fallback
    carries the exception type name as a breadcrumb."""

    def test_plain_object_returns_normal_repr(self) -> None:
        assert _safe_repr(42) == "42"
        assert _safe_repr("hello") == "'hello'"
        assert _safe_repr(None) == "None"

    def test_raising_repr_falls_back(self) -> None:
        class _Evil:
            def __repr__(self) -> str:
                raise RuntimeError("boom")

        out = _safe_repr(_Evil())
        assert "<repr raised>" in out
        assert "RuntimeError" in out

    def test_raising_repr_via_metaclass_falls_back(self) -> None:
        class _EvilMeta(type):
            def __repr__(cls) -> str:
                raise RuntimeError("boom from meta")

        EvilClass = _EvilMeta("EvilClass", (), {})
        out = _safe_repr(EvilClass)
        assert "<repr raised>" in out
        assert "RuntimeError" in out

    def test_repr_raising_systemexit_does_not_propagate(self) -> None:
        """``SystemExit`` is a ``BaseException`` -- the helper must
        catch it so a hostile plugin's ``__repr__`` cannot inject a
        process exit through the discovery walk."""

        class _Evil:
            def __repr__(self) -> str:
                raise SystemExit(0)

        out = _safe_repr(_Evil())
        assert "<repr raised>" in out
        assert "SystemExit" in out

    def test_repr_raising_keyboard_interrupt_does_not_propagate(
        self,
    ) -> None:
        class _Evil:
            def __repr__(self) -> str:
                raise KeyboardInterrupt()

        out = _safe_repr(_Evil())
        assert "<repr raised>" in out
        assert "KeyboardInterrupt" in out

    def test_custom_fallback_string(self) -> None:
        class _Evil:
            def __repr__(self) -> str:
                raise ValueError("bad")

        out = _safe_repr(_Evil(), fallback="<custom>")
        assert out.startswith("<custom>")
        assert "ValueError" in out


class TestF_R19_1_CliHunt_SafeStrHelper:
    """Same shape for ``str()`` of plugin-controlled exceptions."""

    def test_plain_str_returns_normal(self) -> None:
        assert _safe_str("hello") == "hello"

    def test_raising_str_falls_back(self) -> None:
        class _EvilExc(Exception):
            def __str__(self) -> str:
                raise RuntimeError("boom")

        out = _safe_str(_EvilExc())
        assert "<str raised>" in out
        assert "RuntimeError" in out

    def test_str_raising_basexception_does_not_propagate(self) -> None:
        class _Evil:
            def __str__(self) -> str:
                raise SystemExit(1)

        out = _safe_str(_Evil())
        assert "<str raised>" in out
        assert "SystemExit" in out


# ---------------------------------------------------------------------------
# F-R19-1 — hostile __repr__ / __str__ raises do not crash discovery
# ---------------------------------------------------------------------------


class TestF_R19_1_CliHunt_HostileReprDoesNotCrashDiscovery:
    """A hostile plugin whose resolved object's ``__repr__`` raises
    must NOT crash the discovery walk. Later plugins in the entry-point
    list must still be discovered and recorded."""

    def test_non_check_object_with_raising_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Hits the non-Check resolved-object branch
        (``discovery.py:303``). ``ep.load()`` returns an object whose
        metaclass overrides ``__repr__`` to raise -- pre-R19 this
        crashed the whole walk."""

        class _EvilMeta(type):
            def __repr__(cls) -> str:
                raise RuntimeError("boom from class __repr__")

        EvilNonCheck = _EvilMeta("EvilNonCheck", (), {})

        class _GoodNonCheck:
            # Will be filtered out (not a Check subclass), but that's
            # not the point -- the point is it gets recorded as a
            # load_error row AFTER the evil one, so we can verify the
            # walk didn't abort.
            pass

        class _EvilEP:
            name = "evil_repr_plugin"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                return EvilNonCheck

        class _GoodEP:
            name = "second_plugin"
            value = "fakemod:good"
            dist = None

            def load(self) -> object:
                return _GoodNonCheck

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP(), _GoodEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        # Pre-R19 this raised RuntimeError out of discover_plugins.
        plugins = plugin_discovery.discover_plugins(refresh=True)

        # Both plugins must be recorded.
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"evil_repr_plugin", "second_plugin"}
        evil = next(p for p in plugins if p.name == "evil_repr_plugin")
        assert evil.status == "load_error"
        assert evil.error is not None
        # The breadcrumb names the offending exception type so the
        # operator can debug.
        assert "RuntimeError" in evil.error

        plugin_discovery.reset_cache()

    def test_declared_abi_with_raising_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Hits the non-integer CHECK_ABI_VERSION branch
        (``discovery.py:335``). A Check subclass declares
        ``CHECK_ABI_VERSION`` as an instance whose ``__repr__`` raises.
        Pre-R19 this crashed the walk."""

        from signet.core.check import Check, CheckResult, Stage

        class _EvilDeclared:
            def __repr__(self) -> str:
                raise RuntimeError("boom from declared __repr__")

        class _EvilCheck(Check):
            CHECK_ABI_VERSION = _EvilDeclared()  # type: ignore[assignment]
            name = "_evil_check"
            stage = Stage.ADMISSION

            async def pre_request(self, ctx):  # type: ignore[override]
                return CheckResult.allow()

        class _SecondCheck(Check):
            CHECK_ABI_VERSION = 999  # incompatible but recordable
            name = "_second_check"
            stage = Stage.ADMISSION

            async def pre_request(self, ctx):  # type: ignore[override]
                return CheckResult.allow()

        class _EvilEP:
            name = "evil_declared_plugin"
            value = "fakemod:evilcheck"
            dist = None

            def load(self) -> type[Check]:
                return _EvilCheck

        class _SecondEP:
            name = "second_check_plugin"
            value = "fakemod:secondcheck"
            dist = None

            def load(self) -> type[Check]:
                return _SecondCheck

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP(), _SecondEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        # Pre-R19 this raised RuntimeError out of discover_plugins.
        plugins = plugin_discovery.discover_plugins(refresh=True)
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"evil_declared_plugin", "second_check_plugin"}

        evil = next(p for p in plugins if p.name == "evil_declared_plugin")
        assert evil.status == "incompatible_abi"
        assert evil.error is not None
        assert "RuntimeError" in evil.error

        plugin_discovery.reset_cache()

    def test_load_exception_with_raising_str(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Hits the load-error branch's ``str(exc)`` site
        (``discovery.py:268``). A custom exception class overrides
        ``__str__`` to raise. Pre-R19 this crashed the walk."""

        class _EvilExc(Exception):
            def __str__(self) -> str:
                raise RuntimeError("boom from exc __str__")

        class _EvilEP:
            name = "evil_exc_plugin"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise _EvilExc("ignored")

        class _SecondEP:
            name = "second_after_exc"
            value = "fakemod:second"
            dist = None

            def load(self) -> object:
                # Anything non-Check -- it just needs to be recorded.
                return 42

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP(), _SecondEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        plugins = plugin_discovery.discover_plugins(refresh=True)
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"evil_exc_plugin", "second_after_exc"}

        evil = next(p for p in plugins if p.name == "evil_exc_plugin")
        assert evil.status == "load_error"
        assert evil.error is not None
        # Exception type name is recorded as the load-error class.
        assert "_EvilExc" in evil.error

        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R19-2 — except BaseException widens the guard, signals re-raise
# ---------------------------------------------------------------------------


class TestF_R19_2_CliHunt_BaseExceptionGuard:
    """A hostile plugin whose ``ep.load()`` raises a ``BaseException``
    subclass (``GeneratorExit``, ``MemoryError``, etc.) is treated as
    a load failure and the discovery walk continues. The exceptions
    that genuinely propagate operator/process intent
    (``KeyboardInterrupt``, ``SystemExit``) still escape."""

    def test_generatorexit_caught_and_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _EvilEP:
            name = "evil_generatorexit"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise GeneratorExit("plugin tried to inject GeneratorExit")

        class _SecondEP:
            name = "second_after_gen"
            value = "fakemod:good"
            dist = None

            def load(self) -> object:
                return 0  # non-Check, recorded as load_error downstream

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP(), _SecondEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        # Pre-R19 ``except Exception`` did not catch GeneratorExit so
        # this propagated and the second plugin was never reached.
        plugins = plugin_discovery.discover_plugins(refresh=True)
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"evil_generatorexit", "second_after_gen"}

        evil = next(p for p in plugins if p.name == "evil_generatorexit")
        assert evil.status == "load_error"
        assert evil.error is not None
        assert "GeneratorExit" in evil.error

        plugin_discovery.reset_cache()

    def test_keyboardinterrupt_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An operator's Ctrl+C during discovery must still surface --
        we do NOT swallow KeyboardInterrupt as a load failure."""

        class _EvilEP:
            name = "evil_kbinterrupt"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise KeyboardInterrupt()

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        with pytest.raises(KeyboardInterrupt):
            plugin_discovery.discover_plugins(refresh=True)

        plugin_discovery.reset_cache()

    def test_systemexit_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A plugin that calls ``sys.exit()`` on import is a deliberate
        process-exit signal and must propagate. Operators who want a
        softer failure for this case should wrap their plugin code in
        a regular ``Exception`` raise."""

        class _ExitEP:
            name = "exit_plugin"
            value = "fakemod:exit"
            dist = None

            def load(self) -> object:
                raise SystemExit(0)

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_ExitEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        with pytest.raises(SystemExit):
            plugin_discovery.discover_plugins(refresh=True)

        plugin_discovery.reset_cache()

    def test_regular_exception_still_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Smoke test: a normal ``Exception`` is still caught and
        recorded just like pre-R19 -- we widened the guard, we
        didn't replace it."""

        class _EvilEP:
            name = "evil_regular"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise ImportError("module not found")

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        plugins = plugin_discovery.discover_plugins(refresh=True)
        assert len(plugins) == 1
        assert plugins[0].status == "load_error"
        assert plugins[0].error is not None
        assert "ImportError" in plugins[0].error

        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R19-1 sweep — every plugin-controlled repr/str site uses a safe helper
# ---------------------------------------------------------------------------


class TestF_R19_1_CliHunt_SourceSweep:
    """Source-level audit: every ``repr(...)`` / ``str(...)`` call AND
    every ``__name__`` / ``__class__`` attribute access on a plugin-
    controlled value in ``discovery.py`` MUST go through
    ``_safe_repr`` / ``_safe_str`` / ``_safe_name``. A future refactor
    that reintroduces a bare ``repr(obj)`` / ``type(exc).__name__`` /
    ``obj.__name__`` on a plugin-controlled object will trip this test.

    Round 21 (F-R21-2) extended the sweep to cover attribute-access
    patterns -- the R19 sweep only flagged ``Call(repr|str, ...)``
    and a hostile metaclass ``__getattribute__`` that raises on
    ``__name__`` slipped past as a result.
    """

    # The names of plugin-controlled locals that flow into the
    # repr/str/name surface. A bare ``repr(<one of these>)`` or
    # ``<one of these>.__name__`` outside the helpers is a regression.
    _PLUGIN_CONTROLLED_NAMES: ClassVar[set[str]] = {"obj", "declared", "exc"}

    def _helper_ranges(self, tree: ast.AST) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in {
                "_safe_repr",
                "_safe_str",
                "_safe_name",
            }:
                end = node.end_lineno or node.lineno
                ranges.append((node.lineno, end))
        return ranges

    def test_no_bare_repr_or_str_of_plugin_values(self) -> None:
        source = Path(plugin_discovery.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)

        helper_ranges = self._helper_ranges(tree)
        # ``_safe_repr`` + ``_safe_str`` + ``_safe_name`` (R21 added the
        # third helper).
        assert len(helper_ranges) == 3, (
            "expected to find _safe_repr, _safe_str, and _safe_name helpers"
        )

        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id in {"repr", "str"}):
                continue
            # Skip inside the helper definitions.
            if any(lo <= node.lineno <= hi for lo, hi in helper_ranges):
                continue
            if not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in self._PLUGIN_CONTROLLED_NAMES:
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"{func.id}({arg.id}) -- use "
                    f"_safe_{func.id}({arg.id}) instead"
                )

        assert not offenders, "\n".join(offenders)

    def test_no_bare_name_attribute_access_on_plugin_values(self) -> None:
        """Round 21 F-R21-2: every ``__name__`` / ``__class__``
        attribute access on a plugin-controlled local must go through
        ``_safe_name``. Three attribute-access patterns are flagged:

        * ``Attribute(value=Name(plugin_local), attr='__name__')`` --
          direct ``obj.__name__``.
        * ``Attribute(value=Call(func=Name('type'),
          args=[Name(plugin_local)]), attr='__name__')`` --
          ``type(obj).__name__``.
        * ``Attribute(value=Attribute(value=Name(plugin_local),
          attr='__class__'), attr='__name__')`` --
          ``obj.__class__.__name__``.

        The ``_safe_name`` / ``_safe_repr`` / ``_safe_str`` helper
        bodies are exempt (they contain the ONE allowed bare
        ``obj.__name__`` / ``type(obj).__name__`` access).
        """
        source = Path(plugin_discovery.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        helper_ranges = self._helper_ranges(tree)

        def _in_helper(lineno: int) -> bool:
            return any(lo <= lineno <= hi for lo, hi in helper_ranges)

        def _is_plugin_local(node: ast.AST) -> bool:
            return isinstance(node, ast.Name) and node.id in self._PLUGIN_CONTROLLED_NAMES

        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr not in {"__name__", "__class__"}:
                continue
            if _in_helper(node.lineno):
                continue

            value = node.value
            # Case 1: direct ``obj.__name__`` / ``obj.__class__``.
            if _is_plugin_local(value):
                assert isinstance(value, ast.Name)
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"{value.id}.{node.attr} -- use "
                    f"_safe_name({value.id}) instead"
                )
                continue
            # Case 2: ``type(obj).__name__``.
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "type"
                and value.args
                and _is_plugin_local(value.args[0])
            ):
                inner = value.args[0]
                assert isinstance(inner, ast.Name)
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"type({inner.id}).{node.attr} -- use "
                    f"_safe_name({inner.id}) instead"
                )
                continue
            # Case 3: ``obj.__class__.__name__``.
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "__class__"
                and _is_plugin_local(value.value)
            ):
                inner = value.value
                assert isinstance(inner, ast.Name)
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"{inner.id}.__class__.{node.attr} -- use "
                    f"_safe_name({inner.id}) instead"
                )
                continue

        assert not offenders, "\n".join(offenders)

    def test_no_bare_getattr_or_vars_on_plugin_values(self) -> None:
        """Round 23 F-R23-7: extend the AST sweep to cover
        ``getattr(obj, '__name__')`` (and ``__qualname__`` /
        ``__class__``), chained ``obj.foo.__name__`` patterns, and
        ``vars(obj)`` on a plugin-controlled local. These are all
        attribute-access shapes that a hostile metaclass can subvert
        the same way as a direct ``obj.__name__`` access.

        ``__qualname__`` is included because Python falls back to it
        when ``__name__`` is missing; hostile plugins targeting one
        will typically also target the other.
        """
        source = Path(plugin_discovery.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        helper_ranges = self._helper_ranges(tree)

        def _in_helper(lineno: int) -> bool:
            return any(lo <= lineno <= hi for lo, hi in helper_ranges)

        def _is_plugin_local(node: ast.AST) -> bool:
            return isinstance(node, ast.Name) and node.id in self._PLUGIN_CONTROLLED_NAMES

        flagged_attrs = {"__name__", "__qualname__", "__class__"}
        offenders: list[str] = []

        for node in ast.walk(tree):
            if _in_helper(getattr(node, "lineno", 0)):
                continue
            # Pattern A: ``getattr(plugin_local, '__name__' | ...)`` and
            # ``vars(plugin_local)``.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "vars" and node.args:
                    arg = node.args[0]
                    if _is_plugin_local(arg):
                        assert isinstance(arg, ast.Name)
                        offenders.append(
                            f"discovery.py:{node.lineno}: bare "
                            f"vars({arg.id}) -- attribute access on a "
                            "plugin-controlled value should go through "
                            "_safe_getattr"
                        )
                        continue
                if (
                    node.func.id == "getattr"
                    and len(node.args) >= 2
                    and _is_plugin_local(node.args[0])
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in flagged_attrs
                ):
                    target = node.args[0]
                    attr_node = node.args[1]
                    assert isinstance(target, ast.Name)
                    offenders.append(
                        f"discovery.py:{node.lineno}: bare "
                        f"getattr({target.id}, {attr_node.value!r}) -- "
                        f"use _safe_name({target.id}) or "
                        f"_safe_getattr({target.id}, ...) instead"
                    )
                    continue
            # Pattern B: chained ``obj.foo.__name__`` — Attribute whose
            # value chain ends in a plugin-controlled Name.
            if isinstance(node, ast.Attribute) and node.attr == "__qualname__":
                # Walk up the .value chain to see if it terminates in a
                # plugin-controlled Name.
                current: ast.AST = node.value
                depth = 0
                while isinstance(current, ast.Attribute) and depth < 6:
                    current = current.value
                    depth += 1
                if _is_plugin_local(current):
                    assert isinstance(current, ast.Name)
                    offenders.append(
                        f"discovery.py:{node.lineno}: bare "
                        f"{current.id}{'.<...>' * depth}.__qualname__ -- "
                        f"use _safe_name(...) instead"
                    )

        assert not offenders, "\n".join(offenders)


# ---------------------------------------------------------------------------
# F-R19-1 — bounded wall-clock still holds with the safe wrappers
# ---------------------------------------------------------------------------


class TestF_R19_1_CliHunt_BoundedWallClock:
    """A plugin whose ``__repr__`` raises must complete discovery in
    well under a second. The R17 truncation cap still applies AFTER
    the safe repr -- we don't lose the F-R15-2 / F-R17-2 bound."""

    def test_raising_repr_does_not_stall(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _EvilMeta(type):
            def __repr__(cls) -> str:
                raise RuntimeError("boom")

        EvilNonCheck = _EvilMeta("EvilNonCheck", (), {})

        class _EvilEP:
            name = "evil_repr_perf"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                return EvilNonCheck

        def _fake_iter(group: str) -> list[_EvilEP]:
            if group == "signet.checks":
                return [_EvilEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        t0 = time.perf_counter()
        plugin_discovery.discover_plugins(refresh=True)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"discovery took {elapsed:.3f}s"

        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R19-3 — signet init reserved device name produces ClickException
# ---------------------------------------------------------------------------


class TestF_R19_3_CliHunt_InitReservedDeviceName:
    """``signet init CON`` (and the other reserved-name variants)
    must surface a ``ClickException`` at the CLI boundary rather than
    a raw ``NotADirectoryError`` traceback from ``Path.mkdir``."""

    @pytest.mark.parametrize(
        "name",
        [
            "CON",
            "NUL",
            "PRN",
            "AUX",
            "COM1",
            "COM9",
            "LPT1",
            "LPT9",
            # Lower / mixed case routes the same way on Win32.
            "con",
            "Con",
            "nul",
            # R15 trailing-space / dot variants must also fire here.
            "CON ",
            "CON.",
            "CON\t",
            # Extension form (CON.txt still routes to the CON device).
            "con.txt",
            "NUL.log",
        ],
    )
    def test_init_rejects_reserved_target_dir(self, name: str) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["init", name])
            # Non-zero exit code (ClickException).
            assert result.exit_code != 0, result.output
            # Canonical message substring.
            assert "Windows reserved device name" in result.output
            # No raw Python traceback in the output -- the operator
            # sees a clean error, not a stack frame dump.
            assert "Traceback" not in result.output
            assert "NotADirectoryError" not in result.output
            # The kind label appears in the message (per R17 helper
            # contract).
            assert "TARGET_DIR" in result.output

    def test_init_helper_call_propagates_kind(self) -> None:
        """The helper raises with the ``TARGET_DIR`` ``kind`` substring
        so the operator-facing error names the offending CLI
        argument."""
        with pytest.raises(click.exceptions.ClickException) as excinfo:
            _reject_windows_reserved_device_name(Path("CON"), kind="TARGET_DIR")
        assert "TARGET_DIR" in str(excinfo.value.message)
        assert "Windows reserved device name" in str(excinfo.value.message)

    def test_init_normal_path_still_works(self, tmp_path: Path) -> None:
        """The guard must not over-reach onto normal directory names.
        Smoke test that a regular ``init`` still scaffolds."""
        runner = CliRunner()
        target = tmp_path / "my_project"
        result = runner.invoke(main, ["init", str(target)])
        assert result.exit_code == 0, result.output
        # The scaffold produced its core artifact.
        assert (target / "pipeline.py").exists()

    def test_init_default_current_dir_still_works(self) -> None:
        """``signet init`` with no arg defaults to ``.`` -- the guard
        must not refuse the current directory (basename "." is not a
        reserved name)."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 0, result.output
            assert Path("pipeline.py").exists()
