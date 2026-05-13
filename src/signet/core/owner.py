"""Owner -- who is accountable for a commit.

Every request that reaches signet must be attributable to an :class:`Owner`.
If no owner can be resolved (no header, no agent ID, no policy mapping, no
trusted-network fallback), the request is refused before any model call.

The owner travels with the audit row. ``owner_type`` answers *what kind of
actor* (human, agent, policy, unresolved). ``owner_id`` is the principal
identifier within that type. ``approval_chain`` records who/what authorized
the request along the way -- useful when an agent action was approved by a
human, or when a policy bundle delegated authority through several layers.

This module is data-only; resolution logic lives in
:mod:`signet.checks.owner_resolution`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class OwnerType(enum.StrEnum):
    """Discriminator for the kind of actor responsible for a commit."""

    HUMAN = "human"
    """A human principal -- typically an email or username asserted via header."""

    AGENT = "agent"
    """An autonomous agent -- identified by its registered agent ID."""

    POLICY = "policy"
    """An organizational policy or rule that authorized the request without a
    direct human or agent claim. Often used for trusted-network or legacy
    callers, or for refusals where the *policy itself* is the actor blocking."""

    UNRESOLVED = "unresolved"
    """No owner could be resolved. Requests with this owner type MUST be refused
    when ``require_owner`` is set on the pipeline."""


def _coerce_owner_type(value: OwnerType | str) -> OwnerType:
    """Coerce ``value`` to an :class:`OwnerType`.

    Accepts the enum directly. Accepts a string and looks it up
    case-insensitively against the enum's values (``"human"``, ``"agent"``,
    ``"policy"``, ``"unresolved"``). Raises :class:`ValueError` on any
    unknown string so the bug surface is "wrong type at the call site"
    rather than "weird state much later".
    """
    if isinstance(value, OwnerType):
        return value
    if isinstance(value, str):
        try:
            return OwnerType(value.lower())
        except ValueError as e:
            valid = sorted(t.value for t in OwnerType)
            raise ValueError(f"unknown OwnerType {value!r}; expected one of {valid}") from e
    raise ValueError(f"OwnerType must be an OwnerType or str, got {type(value).__name__}")


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

            COMMITMENT-stage escalation surfaces this chain in the audit row
            metadata as ``requires_approval_from`` (the full ordered chain as
            a list) and ``current_approver`` (the first link, or ``None`` if
            the chain is empty). Downstream approval workflows read those two
            fields to drive routing. See :doc:`/escalation` (``docs/escalation.md``).

    Constructor ergonomics: positional args still take ``owner_type, owner_id``
    for backwards compatibility, but ``Owner(type=..., id=...)`` is also
    accepted for symmetry with most other libraries' conventions. The
    classmethods :meth:`human`, :meth:`agent`, :meth:`policy`, and
    :meth:`unresolved` remain the recommended path -- they handle the
    ``approval_chain`` for you.
    """

    owner_type: OwnerType
    owner_id: str
    approval_chain: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.owner_type is OwnerType.UNRESOLVED:
            return
        if not self.owner_id:
            raise ValueError(f"Owner of type {self.owner_type!r} requires a non-empty owner_id")

    @classmethod
    def create(
        cls,
        *,
        type: OwnerType | None = None,
        id: str | None = None,
        owner_type: OwnerType | None = None,
        owner_id: str | None = None,
        approval_chain: tuple[str, ...] = (),
    ) -> Owner:
        """Construct an Owner with either ``type=/id=`` or ``owner_type=/owner_id=``.

        Convenience factory for callers that prefer the shorter kwargs.
        Mixing the two pairs raises :class:`ValueError` so the call site
        is unambiguous.
        """
        if type is not None and owner_type is not None:
            raise ValueError("specify either type= or owner_type=, not both")
        if id is not None and owner_id is not None:
            raise ValueError("specify either id= or owner_id=, not both")
        ot = owner_type if owner_type is not None else type
        oid = owner_id if owner_id is not None else id
        if ot is None:
            raise TypeError("Owner.create requires type= or owner_type=")
        ot = _coerce_owner_type(ot)
        return cls(
            owner_type=ot,
            owner_id=oid or "",
            approval_chain=approval_chain,
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
