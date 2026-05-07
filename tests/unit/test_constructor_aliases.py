"""Parametrized tests over every public constructor's accepted input forms.

Lesson learned in 0.1.6: ergonomic kwarg aliases for Owner.create and
KeyRing(keys=) shipped without input-form coverage. Test type tracker:

* Owner: positional, kwargs (long), kwargs (short), accepting str + enum + case
  variants for OwnerType.
* KeyRing: active=, keys=list[Key], keys=dict[str, Key], keys=dict[str, bytes].
* RequestContext: with and without method=, default value.
* Owner.human/agent/policy/unresolved factories.
"""
from __future__ import annotations

import pytest

from signet.audit.keyring import Key, KeyRing
from signet.core.context import RequestContext
from signet.core.owner import Owner, OwnerType


class TestOwnerConstructorForms:
    @pytest.mark.parametrize("type_input,expected", [
        (OwnerType.HUMAN, OwnerType.HUMAN),
        ("human", OwnerType.HUMAN),
        ("HUMAN", OwnerType.HUMAN),
        ("Human", OwnerType.HUMAN),
        (OwnerType.AGENT, OwnerType.AGENT),
        ("agent", OwnerType.AGENT),
        (OwnerType.POLICY, OwnerType.POLICY),
        ("policy", OwnerType.POLICY),
    ])
    def test_create_short_kwargs_coerce_type(self, type_input, expected):
        o = Owner.create(type=type_input, id="x")
        assert o.owner_type is expected
        assert o.owner_id == "x"

    @pytest.mark.parametrize("type_input", [
        OwnerType.HUMAN, "human", "HUMAN",
    ])
    def test_create_long_kwargs_coerce_type(self, type_input):
        o = Owner.create(owner_type=type_input, owner_id="x")
        assert o.owner_type is OwnerType.HUMAN

    def test_create_invalid_type_string_raises(self):
        with pytest.raises(ValueError):
            Owner.create(type="alien", id="x")

    def test_create_str_returns_canonical_form(self):
        # Specifically the bug B1 missed: str(o) blows up with str type
        o = Owner.create(type="human", id="alice")
        assert str(o) == "human:alice"

    @pytest.mark.parametrize("factory,type_,id_", [
        (Owner.human, OwnerType.HUMAN, "alice"),
        (Owner.agent, OwnerType.AGENT, "ai-1"),
        (Owner.policy, OwnerType.POLICY, "internal-tailnet"),
    ])
    def test_named_factories(self, factory, type_, id_):
        o = factory(id_)
        assert o.owner_type is type_
        assert o.owner_id == id_

    def test_unresolved(self):
        o = Owner.unresolved()
        assert o.owner_type is OwnerType.UNRESOLVED
        assert o.owner_id == ""


class TestKeyRingConstructorForms:
    SECRET = b"x" * 32

    def test_legacy_active_form(self):
        kr = KeyRing(active=Key(key_id="k1", secret=self.SECRET))
        assert kr.active.key_id == "k1"

    def test_keys_list_of_Key(self):
        kr = KeyRing(keys=[Key(key_id="k1", secret=self.SECRET)], active_id="k1")
        assert kr.active.key_id == "k1"

    def test_keys_dict_of_Key(self):
        kr = KeyRing(
            keys={"k1": Key(key_id="k1", secret=self.SECRET)},
            active_id="k1",
        )
        assert kr.active.key_id == "k1"

    def test_keys_dict_of_bytes(self):
        # Specifically the bug B2 missed
        kr = KeyRing(keys={"k1": self.SECRET}, active_id="k1")
        assert isinstance(kr.active, Key)
        assert kr.active.key_id == "k1"
        assert kr.active.secret == self.SECRET

    def test_keys_dict_of_bytes_multiple(self):
        kr = KeyRing(
            keys={"k1": self.SECRET, "k2": b"y" * 32},
            active_id="k1",
        )
        assert isinstance(kr.active, Key)
        assert isinstance(kr.get("k2"), Key)


class TestRequestContextConstructor:
    def test_method_defaults_to_post(self):
        ctx = RequestContext(owner=Owner.human("alice"))
        assert ctx.method == "POST"

    def test_method_override(self):
        ctx = RequestContext(owner=Owner.human("alice"), method="GET")
        assert ctx.method == "GET"
