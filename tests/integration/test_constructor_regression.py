"""Integration: constructor-coverage regression for the v0.1.6 B1/B2 gap.

The v0.1.6 bug list captured a coverage gap: ergonomic kwarg aliases
for :class:`signet.core.owner.Owner` (``Owner.create(type=..., id=...)``)
and :class:`signet.audit.keyring.KeyRing` (``KeyRing(keys=dict[str, bytes])``)
shipped without parametrized constructor coverage. The unit-tier fix
landed in ``tests/unit/test_constructor_aliases.py`` and pins:

* ``Owner.create`` with every advertised input form (positional,
  long kwargs, short kwargs, str + enum + case variants).
* ``Owner.human / agent / policy / unresolved`` factory shapes.
* ``KeyRing(active=)`` legacy form.
* ``KeyRing(keys=list[Key])`` form.
* ``KeyRing(keys=dict[str, Key])`` form.
* ``KeyRing(keys=dict[str, bytes])`` form (B2 specifically).

Per the v0.1.7 phase-4 brief: the integration-tier counterpart is
*essentially* the unit suite again. There is no integration value in
re-running every parametrized constructor case behind a TestClient --
constructors are pure data, with no I/O or network. What matters is
that the unit suite is:

1. Present at the expected path.
2. Marked as the canonical home for B1/B2 regressions.
3. Green at the start of every CI run before integration tests fire.

This file pins those properties: it imports the unit module, walks
its test classes, and asserts the expected coverage shape exists. If
somebody renames or deletes the module without restoring the cases
elsewhere, this test fails and surfaces the gap.

If you find yourself wanting to add a new constructor regression, add
it to ``tests/unit/test_constructor_aliases.py`` -- not here.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

# ---------------------------------------------------------------------------
# Pin: the unit module exists and contains the canonical test classes
# ---------------------------------------------------------------------------


def test_unit_constructor_aliases_module_present() -> None:
    """The canonical home for B1/B2 regressions must be importable."""
    mod = importlib.import_module("tests.unit.test_constructor_aliases")
    assert mod is not None


def test_unit_constructor_aliases_class_coverage() -> None:
    """Every class the v0.1.6 audit listed must be present in the
    unit module so a future renamer can't silently drop a test class."""
    mod = importlib.import_module("tests.unit.test_constructor_aliases")
    expected = {
        "TestOwnerConstructorForms",
        "TestKeyRingConstructorForms",
        "TestRequestContextConstructor",
    }
    found = {
        name for name, obj in inspect.getmembers(mod, inspect.isclass)
        if name.startswith("Test")
    }
    missing = expected - found
    assert not missing, (
        f"unit module is missing canonical test classes: {sorted(missing)}; "
        f"add them back to tests/unit/test_constructor_aliases.py rather "
        f"than spreading constructor coverage across files."
    )


def test_unit_keyring_dict_of_bytes_method_exists() -> None:
    """B2 specifically: pin that the
    ``KeyRing(keys=dict[str, bytes])`` test method is present.
    """
    mod = importlib.import_module("tests.unit.test_constructor_aliases")
    cls = mod.TestKeyRingConstructorForms
    methods = [m for m in dir(cls) if m.startswith("test_")]
    assert "test_keys_dict_of_bytes" in methods, (
        "B2 regression test 'test_keys_dict_of_bytes' missing from "
        "TestKeyRingConstructorForms; restore it before tagging."
    )


# ---------------------------------------------------------------------------
# Smoke: constructors actually wire up under integration import order
# ---------------------------------------------------------------------------


class TestConstructorSmoke:
    """A minimal smoke layer over the public constructors.

    The unit suite is the gold-standard test for input-form coverage;
    these cases just confirm the public API is reachable and shaped
    the way the integration tests below it assume.
    """

    def test_owner_short_kwargs_smoke(self) -> None:
        from signet.core.owner import Owner, OwnerType

        o = Owner.create(type="human", id="alice")
        assert o.owner_type is OwnerType.HUMAN
        assert o.owner_id == "alice"

    def test_owner_factories_smoke(self) -> None:
        from signet.core.owner import Owner, OwnerType

        assert Owner.human("a").owner_type is OwnerType.HUMAN
        assert Owner.agent("a").owner_type is OwnerType.AGENT
        assert Owner.policy("a").owner_type is OwnerType.POLICY
        assert Owner.unresolved().owner_type is OwnerType.UNRESOLVED

    def test_keyring_dict_of_bytes_smoke(self) -> None:
        from signet.audit.keyring import Key, KeyRing

        kr = KeyRing(keys={"k1": b"x" * 32}, active_id="k1")
        assert isinstance(kr.active, Key)
        assert kr.active.key_id == "k1"

    def test_keyring_dict_of_Key_smoke(self) -> None:
        from signet.audit.keyring import Key, KeyRing

        k = Key(key_id="k1", secret=b"x" * 32)
        kr = KeyRing(keys={"k1": k}, active_id="k1")
        assert kr.active is k

    def test_request_context_method_default(self) -> None:
        from signet.core.context import RequestContext
        from signet.core.owner import Owner

        ctx = RequestContext(owner=Owner.human("alice"))
        assert ctx.method == "POST"

    @pytest.mark.parametrize(
        "type_input",
        [
            "human",
            "HUMAN",
            "Human",
            "agent",
            "AGENT",
            "policy",
        ],
    )
    def test_owner_string_case_coercion_smoke(self, type_input: str) -> None:
        from signet.core.owner import Owner

        o = Owner.create(type=type_input, id="x")
        # No raise == valid string form.
        assert o.owner_id == "x"
