"""Round 27 hunt closures -- plugin discovery str-subclass / int-subclass leaks.

R26 hardened ``_safe_str_attr`` against ``EntryPoint`` / ``Distribution``
str-subclass returns. The SAME primitive existed in three sibling
helpers and on the ``CHECK_ABI_VERSION`` int comparison/format. R27
closes them uniformly via the ``str.__str__`` / ``int.__int__`` unbound-
dunder coerce pattern.

P0:

- ``F-R27-1 _safe_name leaks str-subclass``: a hostile metaclass whose
  ``__name__`` property returns a ``str``-subclass with raising
  ``__len__`` survived ``isinstance(raw, str)`` (subclass accepted) and
  crashed at the ``len(raw) > 256`` cap inside the helper itself.

- ``F-R27-2 _safe_repr propagates str-subclass``: ``repr(obj)`` invokes
  ``type(obj).__repr__(obj)`` -- if the latter returns a ``str``-subclass
  with raising ``__len__``, ``_truncate_for_log(_safe_repr(obj))``
  crashes on the ``len(s)`` cap one line later.

- ``F-R27-3 _safe_str propagates str-subclass``: same shape as P0-2 but
  on the load-error branch. ``str(exc)`` calls ``type(exc).__str__(exc)``;
  a hostile ``__str__`` returning a hostile str-subclass crashes the
  cached ``exc_str_safe`` build.

HIGH:

- ``F-R27-4 hostile int-subclass __ne__ crashes ABI comparison``:
  ``_safe_isinstance(declared, int)`` accepts an ``int``-subclass; the
  ``declared != CHECK_ABI_VERSION`` comparison dispatches to
  ``declared.__ne__`` which a hostile subclass overrides to raise.

- ``F-R27-5 hostile int-subclass __format__ crashes f-string``: the
  ABI-mismatch message builds ``f"...CHECK_ABI_VERSION={declared}..."``;
  f-string interpolation invokes ``declared.__format__("")`` which a
  hostile subclass overrides to raise.

MED:

- ``F-R27-6 abi_declared cached as hostile int-subclass``: ABI-mismatch
  branch stores the hostile subclass on
  ``DiscoveredPlugin.abi_declared``; ``__post_init__`` only coerced
  string fields, so the subclass survived in the cache and crashed the
  CLI's ``_sanitize_for_terminal(abi)`` -> ``str(value)`` render path.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Hostile primitive shapes -- shared across tests
# ---------------------------------------------------------------------------


class _RaisingLenStr(str):
    """``str`` subclass whose ``__len__`` always raises."""

    def __len__(self) -> int:  # pragma: no cover - raise path
        raise RuntimeError("hostile __len__")


class _RaisingBoolStr(str):
    def __bool__(self) -> bool:  # pragma: no cover - raise path
        raise RuntimeError("hostile __bool__")


class _RaisingHashStr(str):
    def __hash__(self) -> int:  # pragma: no cover - raise path
        raise RuntimeError("hostile __hash__")


class _RaisingStrStr(str):
    def __str__(self) -> str:  # pragma: no cover - raise path
        raise RuntimeError("hostile __str__")


class _RaisingNeInt(int):
    def __ne__(self, other: object) -> bool:  # pragma: no cover - raise path
        raise RuntimeError("hostile __ne__")

    def __hash__(self) -> int:
        # Overriding ``__eq__`` / ``__ne__`` clears ``__hash__`` by
        # default. Restore via the plain ``int`` dunder so dict ops in
        # test fixtures don't trip the subclass.
        return int.__hash__(self)


class _RaisingFormatInt(int):
    def __format__(self, spec: str) -> str:  # pragma: no cover - raise path
        raise RuntimeError("hostile __format__")


class _RaisingStrInt(int):
    def __str__(self) -> str:  # pragma: no cover - raise path
        raise RuntimeError("hostile __str__")


# ---------------------------------------------------------------------------
# P0 -- F-R27-1: _safe_name returns plain str even for str-subclass __name__
# ---------------------------------------------------------------------------


class TestF_R27_1_SafeNameStrSubclassReturn:
    """``_safe_name`` must coerce its return through ``str.__str__`` so a
    hostile metaclass returning a ``str``-subclass from ``__name__``
    cannot crash the internal ``len(raw) > 256`` cap or any downstream
    f-string interpolation."""

    def test_metaclass_name_returns_str_subclass_with_raising_len(self) -> None:
        from signet.plugins.discovery import _safe_name

        class HostileMeta(type):
            @property
            def __name__(cls) -> str:
                return _RaisingLenStr("legit-name")

        class HostileCls(metaclass=HostileMeta):
            pass

        result = _safe_name(HostileCls)
        # Plain ``str`` -- not a ``_RaisingLenStr`` instance.
        assert type(result) is str
        # The hostile ``__len__`` must NOT crash these:
        assert len(result) == 10
        assert bool(result) is True

    def test_metaclass_name_returns_str_subclass_with_raising_bool(self) -> None:
        from signet.plugins.discovery import _safe_name

        class HostileMeta(type):
            @property
            def __name__(cls) -> str:
                return _RaisingBoolStr("legit-name")

        class HostileCls(metaclass=HostileMeta):
            pass

        result = _safe_name(HostileCls)
        assert type(result) is str
        assert bool(result) is True

    def test_metaclass_name_returns_str_subclass_with_raising_hash(self) -> None:
        from signet.plugins.discovery import _safe_name

        class HostileMeta(type):
            @property
            def __name__(cls) -> str:
                return _RaisingHashStr("legit-name")

        class HostileCls(metaclass=HostileMeta):
            pass

        result = _safe_name(HostileCls)
        assert type(result) is str
        # Dict assignment must work without invoking the subclass hash:
        d: dict[str, str] = {result: "ok"}
        assert d[result] == "ok"

    def test_metaclass_name_returns_overlong_str_subclass(self) -> None:
        """The 256-char cap inside ``_safe_name`` invokes ``len(raw)``.
        Without the coerce, a hostile ``__len__`` aborts the cap path
        and the helper never returns. Post-fix, the coerce strips the
        subclass identity FIRST, so the ``len(raw) > 256`` check
        operates on a plain str."""
        from signet.plugins.discovery import _safe_name

        class HostileMeta(type):
            @property
            def __name__(cls) -> str:
                return _RaisingLenStr("x" * 500)

        class HostileCls(metaclass=HostileMeta):
            pass

        result = _safe_name(HostileCls)
        assert type(result) is str
        # 256 cap + marker applied.
        assert len(result) <= 256 + len("... [truncated]")
        assert result.startswith("x" * 256)


# ---------------------------------------------------------------------------
# P0 -- F-R27-2: _safe_repr returns plain str even when __repr__ returns
# a str-subclass
# ---------------------------------------------------------------------------


class TestF_R27_2_SafeReprStrSubclassReturn:
    """``_safe_repr`` must coerce its return through ``str.__str__`` so a
    hostile ``__repr__`` returning a ``str``-subclass cannot crash the
    downstream ``_truncate_for_log(len(s))`` consumer."""

    def test_repr_returns_str_subclass_with_raising_len(self) -> None:
        from signet.plugins.discovery import _safe_repr, _truncate_for_log

        class Hostile:
            def __repr__(self) -> str:
                return _RaisingLenStr("<hostile>")

        result = _safe_repr(Hostile())
        assert type(result) is str
        assert len(result) == 9
        # Mirror the actual downstream consumer:
        truncated = _truncate_for_log(result)
        assert type(truncated) is str

    def test_repr_returns_str_subclass_with_raising_bool(self) -> None:
        from signet.plugins.discovery import _safe_repr

        class Hostile:
            def __repr__(self) -> str:
                return _RaisingBoolStr("<hostile>")

        result = _safe_repr(Hostile())
        assert type(result) is str
        assert bool(result) is True

    def test_repr_returns_str_subclass_with_raising_str(self) -> None:
        """A ``__str__``-raising subclass from ``__repr__`` survived the
        previous R19 closure because ``_safe_repr`` only caught
        ``repr()`` itself raising -- not the case where ``repr()``
        succeeds but returns a subclass whose ``__str__`` raises later
        (e.g. inside ``logging`` ``%s`` formatting)."""
        from signet.plugins.discovery import _safe_repr

        class Hostile:
            def __repr__(self) -> str:
                return _RaisingStrStr("<hostile>")

        result = _safe_repr(Hostile())
        assert type(result) is str
        # ``str(result)`` must NOT invoke the subclass override.
        assert str(result) == "<hostile>"

    def test_repr_still_raising_path_returns_fallback(self) -> None:
        """Regression: the R19 raising-``__repr__`` closure still works."""
        from signet.plugins.discovery import _safe_repr

        class Hostile:
            def __repr__(self) -> str:
                raise RuntimeError("repr-raised")

        result = _safe_repr(Hostile())
        assert type(result) is str
        assert "<repr raised>" in result


# ---------------------------------------------------------------------------
# P0 -- F-R27-3: _safe_str returns plain str even when __str__ returns
# a str-subclass
# ---------------------------------------------------------------------------


class TestF_R27_3_SafeStrStrSubclassReturn:
    """``_safe_str`` must coerce its return through ``str.__str__`` so a
    hostile exception ``__str__`` returning a ``str``-subclass cannot
    crash the load-error reporting path."""

    def test_str_returns_str_subclass_with_raising_len(self) -> None:
        from signet.plugins.discovery import _safe_str

        class HostileExc(Exception):
            def __str__(self) -> str:
                return _RaisingLenStr("boom")

        result = _safe_str(HostileExc())
        assert type(result) is str
        assert len(result) == 4

    def test_str_returns_str_subclass_with_raising_bool(self) -> None:
        from signet.plugins.discovery import _safe_str

        class HostileExc(Exception):
            def __str__(self) -> str:
                return _RaisingBoolStr("boom")

        result = _safe_str(HostileExc())
        assert type(result) is str
        assert bool(result) is True

    def test_str_returns_str_subclass_with_raising_hash(self) -> None:
        from signet.plugins.discovery import _safe_str

        class HostileExc(Exception):
            def __str__(self) -> str:
                return _RaisingHashStr("boom")

        result = _safe_str(HostileExc())
        assert type(result) is str
        d: dict[str, str] = {result: "ok"}
        assert d[result] == "ok"

    def test_str_still_raising_path_returns_fallback(self) -> None:
        """Regression: the R19 raising-``__str__`` closure still works."""
        from signet.plugins.discovery import _safe_str

        class HostileExc(Exception):
            def __str__(self) -> str:
                raise RuntimeError("str-raised")

        result = _safe_str(HostileExc())
        assert type(result) is str
        assert "<str raised>" in result


# ---------------------------------------------------------------------------
# Integration -- F-R27-1/2/3: end-to-end discovery walk does not abort
# ---------------------------------------------------------------------------


class TestF_R27_DiscoveryWalkSurvivesStrSubclassLeaks:
    """End-to-end: a hostile plugin entry point that exercises each of
    the three P0 attack shapes must NOT abort ``discover_plugins``."""

    def _run_discover_with_fake_ep(self, fake_ep: object, monkeypatch: pytest.MonkeyPatch) -> list:
        """Inject ``fake_ep`` as the sole entry point under signet.checks
        and rebuild the discovery cache."""
        from signet.plugins import discovery

        def fake_iter(group: str) -> list:
            if group == "signet.checks":
                return [fake_ep]
            return []

        monkeypatch.setattr(discovery, "_iter_entry_points", fake_iter)
        discovery.reset_cache()
        return discovery.discover_plugins(refresh=True)

    def test_safe_name_subclass_does_not_abort_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Plugin whose class metaclass has a hostile ``__name__``.
        Routes through the non-int-ABI branch and exercises
        ``_safe_name(obj)``."""
        from signet.core.check import Check, Stage

        class HostileMeta(type(Check)):
            @property
            def __name__(cls):
                return _RaisingLenStr("HostileCheck")

        class HostileCheck(Check, metaclass=HostileMeta):
            name = "hostile"
            stage = Stage.ADMISSION
            CHECK_ABI_VERSION = "not-an-int"  # forces _safe_name(obj) branch

            def evaluate(self, request, context):  # pragma: no cover
                pass

        class FakeEP:
            name = "hostile"
            value = "x:y"
            group = "signet.checks"
            dist = None

            def load(self):
                return HostileCheck

        results = self._run_discover_with_fake_ep(FakeEP(), monkeypatch)
        assert len(results) == 1
        assert results[0].status == "incompatible_abi"

    def test_safe_repr_subclass_does_not_abort_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Plugin entry point returns a non-Check object whose
        ``__repr__`` returns a hostile str-subclass."""

        class HostileObj:
            def __repr__(self) -> str:
                return _RaisingLenStr("<hostile>")

        class FakeEP:
            name = "fake"
            value = "x:y"
            group = "signet.checks"
            dist = None

            def load(self):
                return HostileObj()

        results = self._run_discover_with_fake_ep(FakeEP(), monkeypatch)
        assert len(results) == 1
        assert results[0].status == "load_error"

    def test_safe_str_subclass_does_not_abort_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Plugin entry point raises a hostile exception whose
        ``__str__`` returns a str-subclass."""

        class HostileExc(Exception):
            def __str__(self) -> str:
                return _RaisingLenStr("boom")

        class FakeEP:
            name = "fake"
            value = "x:y"
            group = "signet.checks"
            dist = None

            def load(self):
                raise HostileExc("ignored")

        results = self._run_discover_with_fake_ep(FakeEP(), monkeypatch)
        assert len(results) == 1
        assert results[0].status == "load_error"


# ---------------------------------------------------------------------------
# HIGH -- F-R27-4/5: hostile int-subclass CHECK_ABI_VERSION
# ---------------------------------------------------------------------------


class TestF_R27_4_HostileIntSubclassNeDoesNotCrashAbiComparison:
    """A plugin declaring ``CHECK_ABI_VERSION`` as an ``int``-subclass
    with a raising ``__ne__`` must NOT crash the discovery walk at the
    ``declared != CHECK_ABI_VERSION`` comparison."""

    def test_hostile_ne_does_not_abort_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from signet.core.check import CHECK_ABI_VERSION, Check, Stage
        from signet.plugins import discovery

        # Build a hostile value that's an int subclass with the WRONG
        # int value, so the != path is taken AFTER coerce.
        bad_value = CHECK_ABI_VERSION + 999
        hostile_int = _RaisingNeInt(bad_value)

        class HostileCheck(Check):
            name = "hostile"
            stage = Stage.ADMISSION
            CHECK_ABI_VERSION = hostile_int

            def evaluate(self, request, context):  # pragma: no cover
                pass

        class FakeEP:
            name = "hostile"
            value = "x:y"
            group = "signet.checks"
            dist = None

            def load(self):
                return HostileCheck

        def fake_iter(group: str) -> list:
            return [FakeEP()] if group == "signet.checks" else []

        monkeypatch.setattr(discovery, "_iter_entry_points", fake_iter)
        discovery.reset_cache()
        results = discovery.discover_plugins(refresh=True)
        assert len(results) == 1
        # Should land on incompatible_abi (different int value), NOT
        # crash. The hostile ``__ne__`` is bypassed by the coerce.
        assert results[0].status == "incompatible_abi"


class TestF_R27_5_HostileIntSubclassFormatDoesNotCrashAbiMismatchMessage:
    """A plugin whose ``CHECK_ABI_VERSION`` is an int-subclass with a
    raising ``__format__`` must NOT crash the ABI-mismatch f-string
    interpolation. The coerce strips the subclass before format
    dispatch."""

    def test_hostile_format_does_not_abort_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from signet.core.check import CHECK_ABI_VERSION, Check, Stage
        from signet.plugins import discovery

        bad_value = CHECK_ABI_VERSION + 999
        hostile_int = _RaisingFormatInt(bad_value)

        class HostileCheck(Check):
            name = "hostile"
            stage = Stage.ADMISSION
            CHECK_ABI_VERSION = hostile_int

            def evaluate(self, request, context):  # pragma: no cover
                pass

        class FakeEP:
            name = "hostile"
            value = "x:y"
            group = "signet.checks"
            dist = None

            def load(self):
                return HostileCheck

        def fake_iter(group: str) -> list:
            return [FakeEP()] if group == "signet.checks" else []

        monkeypatch.setattr(discovery, "_iter_entry_points", fake_iter)
        discovery.reset_cache()
        results = discovery.discover_plugins(refresh=True)
        assert len(results) == 1
        assert results[0].status == "incompatible_abi"
        # The cached error message contains the coerced plain-int
        # decimal -- no subclass __format__ dispatch.
        assert results[0].error is not None
        assert str(bad_value) in results[0].error


# ---------------------------------------------------------------------------
# MED -- F-R27-6: abi_declared coerced by __post_init__
# ---------------------------------------------------------------------------


class TestF_R27_6_DiscoveredPluginPostInitCoercesAbiDeclared:
    """``DiscoveredPlugin.__post_init__`` must coerce a hostile
    ``int``-subclass ``abi_declared`` to a plain int (or ``None``) so
    the cached value cannot crash the CLI's ``str(value)`` render path
    when surfacing the plugins list."""

    def test_post_init_coerces_int_subclass_with_raising_str(self) -> None:
        from signet.plugins.discovery import DiscoveredPlugin

        hostile = _RaisingStrInt(999)
        plugin = DiscoveredPlugin(
            group="signet.checks",
            name="hostile",
            package="pkg",
            package_version="0.1.0",
            target="mod:Cls",
            status="incompatible_abi",
            abi_declared=hostile,
            abi_required=1,
            error="test",
            obj=None,
        )
        # Plain ``int`` -- not a ``_RaisingStrInt``.
        assert type(plugin.abi_declared) is int
        assert plugin.abi_declared == 999
        # The hostile ``__str__`` must NOT crash the CLI render path:
        assert str(plugin.abi_declared) == "999"

    def test_post_init_coerces_int_subclass_with_raising_format(self) -> None:
        from signet.plugins.discovery import DiscoveredPlugin

        hostile = _RaisingFormatInt(42)
        plugin = DiscoveredPlugin(
            group="signet.checks",
            name="hostile",
            package="pkg",
            package_version="0.1.0",
            target="mod:Cls",
            status="incompatible_abi",
            abi_declared=hostile,
            abi_required=1,
            error="test",
            obj=None,
        )
        assert type(plugin.abi_declared) is int
        # f-string interpolation must NOT invoke the subclass __format__.
        assert f"{plugin.abi_declared}" == "42"

    def test_post_init_coerces_int_subclass_with_raising_ne(self) -> None:
        from signet.plugins.discovery import DiscoveredPlugin

        hostile = _RaisingNeInt(7)
        plugin = DiscoveredPlugin(
            group="signet.checks",
            name="hostile",
            package="pkg",
            package_version="0.1.0",
            target="mod:Cls",
            status="incompatible_abi",
            abi_declared=hostile,
            abi_required=1,
            error="test",
            obj=None,
        )
        assert type(plugin.abi_declared) is int
        # Comparison must NOT invoke the subclass __ne__.
        assert plugin.abi_declared != 999

    def test_post_init_preserves_none(self) -> None:
        from signet.plugins.discovery import DiscoveredPlugin

        plugin = DiscoveredPlugin(
            group="signet.checks",
            name="ok",
            package="pkg",
            package_version="0.1.0",
            target="mod:Cls",
            status="load_error",
            abi_declared=None,
            abi_required=1,
            error="boom",
            obj=None,
        )
        assert plugin.abi_declared is None

    def test_post_init_preserves_plain_int(self) -> None:
        """The happy path: a regular ``int`` survives unchanged."""
        from signet.plugins.discovery import DiscoveredPlugin

        plugin = DiscoveredPlugin(
            group="signet.checks",
            name="ok",
            package="pkg",
            package_version="0.1.0",
            target="mod:Cls",
            status="loaded",
            abi_declared=1,
            abi_required=1,
            error=None,
            obj=None,
        )
        assert plugin.abi_declared == 1
        assert type(plugin.abi_declared) is int

    @pytest.mark.parametrize(
        "junk_value",
        ["not-an-int", 3.14, [1, 2, 3]],
    )
    def test_post_init_handles_non_int_abi_declared(self, junk_value: object) -> None:
        """If somehow a non-int / non-None value lands in
        ``abi_declared`` (e.g. an attacker-constructed dataclass
        bypassing the discovery walk), the coerce defaults to ``None``
        rather than letting the junk leak into the cache."""
        from signet.plugins.discovery import DiscoveredPlugin

        plugin = DiscoveredPlugin(
            group="signet.checks",
            name="ok",
            package="pkg",
            package_version="0.1.0",
            target="mod:Cls",
            status="incompatible_abi",
            abi_declared=junk_value,  # type: ignore[arg-type]
            abi_required=1,
            error="boom",
            obj=None,
        )
        # Coerced to ``None`` (the canonical "unknown ABI" sentinel)
        # rather than leaving the hostile value to crash CLI render.
        assert plugin.abi_declared is None
