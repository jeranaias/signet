"""Owner — who is accountable for a commit.

Every request that reaches signet must be attributable to an :class:`Owner`.
If no owner can be resolved (no header, no agent ID, no policy mapping, no
trusted-network fallback), the request is refused before any model call.

The owner travels with the audit row. ``owner_type`` answers *what kind of
actor* (human, agent, policy, unresolved). ``owner_id`` is the principal
identifier within that type. ``approval_chain`` records who/what authorized
the request along the way — useful when an agent action was approved by a
human, or when a policy bundle delegated authority through several layers.

This module is data-only; resolution logic lives in
:mod:`signet.core.owner_resolver`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class OwnerType(str, enum.Enum):
    """Discriminator for the kind of actor responsible for a commit."""

    HUMAN = "human"
    """A human principal — typically an email or username asserted via header."""

    AGENT = "agent"
    """An autonomous agent — identified by its registered agent ID."""

    POLICY = "policy"
    """An organizational policy or rule that authorized the request without a
    direct human or agent claim. Often used for trusted-network or legacy
    callers, or for refusals where the *policy itself* is the actor blocking."""

    UNRESOLVED = "unresolved"
    """No owner could be resolved. Requests with this owner type MUST be refused
    when ``require_owner`` is set on the pipeline."""


@dataclass(frozen=True, slots=True)
class Owner:
    """Immutable record of who is accountable for a request.

    Attributes:
        owner_type: One of :class:`OwnerType`.
        owner_id: Principal identifier within the type. Empty string is only
            valid when ``owner_type`` is :attr:`OwnerType.UNRESOLVED`.
        approval_chain: Ordered list of authorities that approved this request,
            most-recent last. Each entry is a free-form string conventionally
            shaped as ``"<type>:<id>"`` (e.g. ``"human:alice@example.com"``,
            ``"policy:internal-tailnet:100.90.15.26"``).
    """

    owner_type: OwnerType
    owner_id: str
    approval_chain: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.owner_type is OwnerType.UNRESOLVED:
            return
        if not self.owner_id:
            raise ValueError(
                f"Owner of type {self.owner_type!r} requires a non-empty owner_id"
            )

    @classmethod
    def unresolved(cls) -> Owner:
        """Construct the canonical unresolved owner used for refused requests."""
        return cls(owner_type=OwnerType.UNRESOLVED, owner_id="", approval_chain=())

    @classmethod
    def human(cls, principal: str) -> Owner:
        """Construct a human owner from a principal (email, username)."""
        return cls(
            owner_type=OwnerType.HUMAN,
            owner_id=principal,
            approval_chain=(f"human:{principal}",),
        )

    @classmethod
    def agent(cls, agent_id: str) -> Owner:
        """Construct an agent owner from a registered agent ID."""
        return cls(
            owner_type=OwnerType.AGENT,
            owner_id=agent_id,
            approval_chain=(f"agent:{agent_id}",),
        )

    @classmethod
    def policy(cls, policy_id: str) -> Owner:
        """Construct a policy owner (e.g. ``"internal-loopback"``,
        ``"acme-policy@v3"``)."""
        return cls(
            owner_type=OwnerType.POLICY,
            owner_id=policy_id,
            approval_chain=(f"policy:{policy_id}",),
        )

    @property
    def is_resolved(self) -> bool:
        """``True`` if this owner is anything other than :attr:`OwnerType.UNRESOLVED`."""
        return self.owner_type is not OwnerType.UNRESOLVED

    def __str__(self) -> str:
        return f"{self.owner_type.value}:{self.owner_id}" if self.is_resolved else "unresolved"
