"""AuditEntry -- the immutable record of one decision.

Every decision the pipeline makes -- *allow*, *block*, *redact*, *escalate* --
becomes one :class:`AuditEntry`. Entries are append-only; once written to the
audit chain they are never modified. Tampering is detected by the HMAC chain
in :mod:`signet.audit`.

This module is data-only. The chain that signs and stores entries lives
separately so this module has zero crypto dependencies and can be safely
imported anywhere.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from signet.core.owner import Owner


class Decision(enum.StrEnum):
    """The outcome of evaluating a request through one or more checks."""

    ALLOW = "allow"
    """Request passed all checks; forward to upstream."""

    BLOCK = "block"
    """Request refused; do not forward. Caller receives an error response."""

    REDACT = "redact"
    """Request forwarded but with content modifications (e.g. PII removed)."""

    ESCALATE = "escalate"
    """Request requires out-of-band human approval before any further action."""


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One immutable decision record.

    ``entry_id`` and ``ts_ns`` are populated automatically when the entry is
    constructed. ``prev_hmac`` and ``hmac`` are populated by the chain writer
    in :mod:`signet.audit.chain` and remain empty strings on free-standing
    entries.

    Attributes:
        entry_id: Unique UUIDv4 identifier for this entry.
        ts_ns: Wall-clock nanoseconds since the Unix epoch when the decision
            was made.
        owner: The accountable :class:`Owner` for the request.
        check_name: Name of the :class:`Check` that produced the decision, or
            ``"pipeline"`` when the decision is the pipeline's aggregated
            result.
        decision: The :class:`Decision` produced.
        reason: Human-readable rationale, ideally short and policy-tagged
            (e.g. ``"owner-resolution: no header present"``).
        request_fingerprint: Stable hash of the request body or its salient
            fields. Used for cross-referencing without leaking full payloads.
        metadata: Free-form structured detail. Use sparingly; prefer dedicated
            fields where possible.
        prev_hmac: HMAC of the immediately-previous chain entry. Populated by
            the chain writer.
        hmac: HMAC of this entry's payload (excluding ``hmac`` itself, but
            including ``prev_hmac``). Populated by the chain writer.
    """

    owner: Owner
    check_name: str
    decision: Decision
    reason: str
    request_fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts_ns: int = field(default_factory=time.time_ns)
    prev_hmac: str = ""
    hmac: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-ready dict.

        ``owner`` is flattened to discrete columns for log-query ergonomics
        (``owner_type``, ``owner_id``, ``approval_chain``) rather than a
        nested object. The :class:`Decision` enum is unwrapped to its string
        value for the same reason.
        """
        d = asdict(self)
        # Flatten owner for log readability and cheap grep'ability.
        owner = d.pop("owner")
        d["owner_type"] = owner["owner_type"]
        d["owner_id"] = owner["owner_id"]
        d["approval_chain"] = list(owner["approval_chain"])
        # Unwrap enum to wire-format string.
        d["decision"] = self.decision.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Inverse of :meth:`to_dict`. Used by the chain verifier when reading
        previously-written entries from disk."""
        from signet.core.owner import OwnerType

        return cls(
            owner=Owner(
                owner_type=OwnerType(data["owner_type"]),
                owner_id=data["owner_id"],
                approval_chain=tuple(data.get("approval_chain", ())),
            ),
            check_name=data["check_name"],
            decision=Decision(data["decision"]),
            reason=data["reason"],
            request_fingerprint=data.get("request_fingerprint", ""),
            metadata=dict(data.get("metadata", {})),
            entry_id=data["entry_id"],
            ts_ns=data["ts_ns"],
            prev_hmac=data.get("prev_hmac", ""),
            hmac=data.get("hmac", ""),
        )

    def with_chain_links(self, prev_hmac: str, hmac: str) -> AuditEntry:
        """Return a new entry with chain HMACs populated.

        Frozen dataclasses can't be mutated; this is the canonical way for the
        chain writer to add the cryptographic links to a fresh entry before
        appending it to disk.
        """
        from dataclasses import replace

        return replace(self, prev_hmac=prev_hmac, hmac=hmac)
