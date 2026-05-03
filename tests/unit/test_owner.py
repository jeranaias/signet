"""Tests for signet.core.owner."""

from __future__ import annotations

import pytest

from signet.core.owner import Owner, OwnerType


class TestOwnerConstructors:
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
