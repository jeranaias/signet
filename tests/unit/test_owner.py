"""Tests for signet.core.owner."""

from __future__ import annotations

import pytest

from signet.core.owner import Owner, OwnerType


class TestOwnerConstructors:
    def test_create_accepts_short_kwargs(self) -> None:
        # v0.1.5 #7 ergonomic alias: Owner.create(type=, id=) maps to
        # Owner(owner_type=, owner_id=).
        o = Owner.create(type=OwnerType.HUMAN, id="alice@example.com")
        assert o.owner_type is OwnerType.HUMAN
        assert o.owner_id == "alice@example.com"

    def test_create_accepts_long_kwargs(self) -> None:
        o = Owner.create(owner_type=OwnerType.AGENT, owner_id="rolling-memory")
        assert o.owner_type is OwnerType.AGENT
        assert o.owner_id == "rolling-memory"

    def test_create_rejects_mixed_kwargs(self) -> None:
        with pytest.raises(ValueError):
            Owner.create(type=OwnerType.HUMAN, owner_type=OwnerType.AGENT, id="x")
        with pytest.raises(ValueError):
            Owner.create(type=OwnerType.HUMAN, id="a", owner_id="b")

    def test_create_requires_a_type(self) -> None:
        with pytest.raises(TypeError):
            Owner.create(id="alice")

    @pytest.mark.parametrize(
        "type_input",
        [OwnerType.HUMAN, "human", "HUMAN", "Human"],
    )
    def test_owner_create_coerces_type(self, type_input: object) -> None:
        # v0.1.6 B1 regression: Owner.create(type="human", ...) had been
        # storing the raw string instead of OwnerType.HUMAN, breaking
        # `owner.owner_type is OwnerType.HUMAN` and str(o).
        o = Owner.create(type=type_input, id="x")  # type: ignore[arg-type]
        assert o.owner_type is OwnerType.HUMAN
        assert str(o) == "human:x"

    def test_create_invalid_type_string_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown OwnerType"):
            Owner.create(type="alien", id="x")

    def test_human_constructor_sets_type_id_and_chain(self) -> None:
        o = Owner.human("alice@example.com")
        assert o.owner_type is OwnerType.HUMAN
        assert o.owner_id == "alice@example.com"
        assert o.approval_chain == ("human:alice@example.com",)

    def test_agent_constructor_sets_type_id_and_chain(self) -> None:
        o = Owner.agent("rolling-memory")
        assert o.owner_type is OwnerType.AGENT
        assert o.owner_id == "rolling-memory"
        assert o.approval_chain == ("agent:rolling-memory",)

    def test_policy_constructor_sets_type_id_and_chain(self) -> None:
        o = Owner.policy("internal-loopback")
        assert o.owner_type is OwnerType.POLICY
        assert o.owner_id == "internal-loopback"
        assert o.approval_chain == ("policy:internal-loopback",)

    def test_unresolved_has_empty_id_and_chain(self) -> None:
        o = Owner.unresolved()
        assert o.owner_type is OwnerType.UNRESOLVED
        assert o.owner_id == ""
        assert o.approval_chain == ()


class TestOwnerInvariants:
    def test_resolved_owner_with_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty owner_id"):
            Owner(owner_type=OwnerType.HUMAN, owner_id="")

    def test_owner_is_frozen(self) -> None:
        o = Owner.human("alice@example.com")
        with pytest.raises(AttributeError):
            o.owner_id = "bob"  # type: ignore[misc]

    def test_owner_is_hashable(self) -> None:
        # Frozen dataclass should be usable as set/dict key
        o1 = Owner.human("alice@example.com")
        o2 = Owner.human("alice@example.com")
        assert {o1, o2} == {o1}

    def test_unresolved_does_not_require_id(self) -> None:
        # Sanity check: unresolved is the one case that allows empty id
        o = Owner(owner_type=OwnerType.UNRESOLVED, owner_id="")
        assert o.owner_type is OwnerType.UNRESOLVED


class TestOwnerHelpers:
    @pytest.mark.parametrize(
        ("ctor", "expected"),
        [
            (lambda: Owner.human("alice"), True),
            (lambda: Owner.agent("a1"), True),
            (lambda: Owner.policy("internal"), True),
            (lambda: Owner.unresolved(), False),
        ],
    )
    def test_is_resolved(self, ctor: object, expected: bool) -> None:
        assert ctor().is_resolved is expected  # type: ignore[operator]

    def test_str_for_resolved(self) -> None:
        assert str(Owner.human("alice@example.com")) == "human:alice@example.com"
        assert str(Owner.agent("rm")) == "agent:rm"
        assert str(Owner.policy("internal")) == "policy:internal"

    def test_str_for_unresolved(self) -> None:
        assert str(Owner.unresolved()) == "unresolved"


class TestOwnerTypeEnum:
    def test_owner_type_values_are_lowercase(self) -> None:
        # Wire-format compatibility: lowercase strings for header values
        for t in OwnerType:
            assert t.value == t.value.lower()

    def test_owner_type_membership(self) -> None:
        assert {t.value for t in OwnerType} == {"human", "agent", "policy", "unresolved"}
