"""Tests for signet.core.audit (AuditEntry + Decision)."""

from __future__ import annotations

import pytest

from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner, OwnerType


class TestDecisionEnum:
    def test_values_are_lowercase_strings(self) -> None:
        for d in Decision:
            assert d.value == d.value.lower()

    def test_membership(self) -> None:
        assert {d.value for d in Decision} == {"allow", "block", "redact", "escalate"}


class TestAuditEntryConstruction:
    def _entry(self, **overrides: object) -> AuditEntry:
        defaults = {
            "owner": Owner.human("alice@example.com"),
            "check_name": "owner_resolution",
            "decision": Decision.ALLOW,
            "reason": "header X-Commit-Owner present",
        }
        defaults.update(overrides)
        return AuditEntry(**defaults)  # type: ignore[arg-type]

    def test_minimal_entry_populates_id_and_ts(self) -> None:
        e = self._entry()
        assert e.entry_id  # non-empty UUID string
        assert len(e.entry_id) == 36
        assert e.ts_ns > 0
        assert e.prev_hmac == ""
        assert e.hmac == ""
        assert e.metadata == {}
        assert e.request_fingerprint == ""

    def test_two_entries_have_distinct_ids(self) -> None:
        e1 = self._entry()
        e2 = self._entry()
        assert e1.entry_id != e2.entry_id

    def test_entry_is_frozen(self) -> None:
        e = self._entry()
        with pytest.raises(AttributeError):
            e.reason = "mutated"  # type: ignore[misc]


class TestAuditEntryRoundtrip:
    def test_to_dict_flattens_owner(self) -> None:
        e = AuditEntry(
            owner=Owner.human("alice@example.com"),
            check_name="owner_resolution",
            decision=Decision.ALLOW,
            reason="present",
            request_fingerprint="sha256:abc",
            metadata={"path": "/v1/chat/completions"},
        )
        d = e.to_dict()
        # Owner is flattened, not nested:
        assert "owner" not in d
        assert d["owner_type"] == "human"
        assert d["owner_id"] == "alice@example.com"
        assert d["approval_chain"] == ["human:alice@example.com"]
        # Decision is unwrapped to wire string:
        assert d["decision"] == "allow"
        # Other fields:
        assert d["check_name"] == "owner_resolution"
        assert d["reason"] == "present"
        assert d["request_fingerprint"] == "sha256:abc"
        assert d["metadata"] == {"path": "/v1/chat/completions"}

    def test_from_dict_inverts_to_dict(self) -> None:
        original = AuditEntry(
            owner=Owner.agent("rolling-memory"),
            check_name="rate_limit",
            decision=Decision.BLOCK,
            reason="quota exceeded",
            request_fingerprint="sha256:xyz",
            metadata={"tokens_requested": 5000, "remaining": 0},
        )
        roundtripped = AuditEntry.from_dict(original.to_dict())
        # Compare structurally — UUIDs and timestamps preserved
        assert roundtripped.owner == original.owner
        assert roundtripped.check_name == original.check_name
        assert roundtripped.decision == original.decision
        assert roundtripped.reason == original.reason
        assert roundtripped.request_fingerprint == original.request_fingerprint
        assert roundtripped.metadata == original.metadata
        assert roundtripped.entry_id == original.entry_id
        assert roundtripped.ts_ns == original.ts_ns

    def test_from_dict_handles_missing_optional_fields(self) -> None:
        # A minimal log row from an external source — only required keys
        minimal = {
            "owner_type": "human",
            "owner_id": "alice",
            "check_name": "owner_resolution",
            "decision": "allow",
            "reason": "ok",
            "entry_id": "00000000-0000-0000-0000-000000000000",
            "ts_ns": 1700000000000000000,
        }
        e = AuditEntry.from_dict(minimal)
        assert e.owner.owner_type is OwnerType.HUMAN
        assert e.owner.owner_id == "alice"
        assert e.metadata == {}
        assert e.owner.approval_chain == ()
        assert e.prev_hmac == ""
        assert e.hmac == ""


class TestAuditEntryChainLinks:
    def test_with_chain_links_returns_new_entry_with_hmacs(self) -> None:
        e = AuditEntry(
            owner=Owner.policy("internal-loopback"),
            check_name="owner_resolution",
            decision=Decision.ALLOW,
            reason="loopback",
        )
        linked = e.with_chain_links(prev_hmac="prev123", hmac="now456")
        assert linked.prev_hmac == "prev123"
        assert linked.hmac == "now456"
        # Original is unchanged (frozen):
        assert e.prev_hmac == ""
        assert e.hmac == ""
        # All other fields preserved:
        assert linked.entry_id == e.entry_id
        assert linked.ts_ns == e.ts_ns
        assert linked.owner == e.owner
        assert linked.check_name == e.check_name
        assert linked.decision == e.decision
        assert linked.reason == e.reason
