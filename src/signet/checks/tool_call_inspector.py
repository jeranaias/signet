"""ToolCallInspectorCheck — risk-tier gating for proposed tool invocations.

Runs at the COMMITMENT stage. Every tool call the model proposes is
inspected before the tool actually runs. Decisions:

* **Allow**: tool is on the allowlist *and* its risk tier is below the
  configured ceiling.
* **Block**: tool is not on the allowlist, OR risk tier exceeds ceiling.
* **Escalate**: risk tier is at or above ``escalate_at_tier`` AND the
  tool is irreversible. The proxy suspends the call pending out-of-band
  human approval.

Tool metadata comes from a registry passed at construction time. Each
entry minimally has:

* ``risk_tier``: ``"low" | "medium" | "high" | "critical"``
* ``irreversible``: bool — true for actions like file deletion, payment,
  external API mutations.
* ``dryrun_supported``: bool — whether the tool can be invoked in
  preview-only mode by the sandbox plugin (out of this check's scope).

Tools missing from the registry are *blocked by default* — register an
empty entry to allow without restrictions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from signet.core.check import Check, CheckResult
from signet.core.context import ToolCallContext
from signet.core.stage import Stage


class RiskTier(enum.IntEnum):
    """Standard risk tiers for tool calls. Higher = more dangerous."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


_TIER_ALIASES: dict[str, RiskTier] = {
    "low": RiskTier.LOW,
    "medium": RiskTier.MEDIUM,
    "high": RiskTier.HIGH,
    "critical": RiskTier.CRITICAL,
}


def _coerce_tier(value: str | int | RiskTier) -> RiskTier:
    """Accept ``"low"`` / ``"high"`` / ``RiskTier.LOW`` / ``2`` interchangeably."""
    if isinstance(value, RiskTier):
        return value
    if isinstance(value, int):
        return RiskTier(value)
    return _TIER_ALIASES[str(value).strip().lower()]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Registry entry for one tool.

    :class:`ToolSpec` is the **canonical source** for tool metadata.
    Other components (e.g. :class:`signet.plugins.sandbox.SandboxPreviewCheck`)
    that need the same fields read them from here via
    :meth:`as_metadata` rather than expecting a parallel
    :attr:`signet.core.context.ToolCallContext.tool_metadata` dict to be
    populated by hand.

    Attributes:
        risk_tier: One of LOW / MEDIUM / HIGH / CRITICAL. Accepts the
            enum, an integer ordinal, or a lowercase string for
            ergonomics in YAML / JSON-loaded registries.
        irreversible: ``True`` for actions that cannot be undone (delete,
            send, transfer, irrevocably mutate). Used by the escalation
            policy.
        dryrun_supported: ``True`` if the sandbox can preview this tool
            without committing. Affects whether escalation is required
            (a dry-runnable tool can preview-then-commit).
    """

    risk_tier: RiskTier = RiskTier.LOW
    irreversible: bool = False
    dryrun_supported: bool = False

    def __post_init__(self) -> None:
        # Accept string / int input but normalize to RiskTier enum
        if not isinstance(self.risk_tier, RiskTier):
            object.__setattr__(self, "risk_tier", _coerce_tier(self.risk_tier))

    def as_metadata(self) -> dict[str, Any]:
        """Project this spec into the ``tool_metadata`` dict shape.

        :class:`signet.core.context.ToolCallContext.tool_metadata`
        accepts free-form data; the conventional keys
        (``risk_tier``, ``irreversible``, ``dryrun_supported``) come
        from here so consumers like the sandbox plugin do not need a
        second registry. Use this when populating
        ``ToolCallContext.tool_metadata`` from a registered spec.
        """
        return {
            "risk_tier": self.risk_tier.name.lower(),
            "irreversible": self.irreversible,
            "dryrun_supported": self.dryrun_supported,
        }


@dataclass
class ToolCallInspectorCheck(Check):
    """COMMITMENT-stage check: gate every tool call by risk tier.

    Args:
        registry: Tool name → :class:`ToolSpec`. Tools not in the registry
            are blocked by default.
        max_allowed_tier: Highest tier a tool may have to be allowed.
            Defaults to HIGH; CRITICAL tools always require explicit
            opt-in via ``allow_critical=True``.
        escalate_at_tier: Tier at which an irreversible tool triggers
            escalation instead of allow. Defaults to HIGH.
        allow_critical: When ``True``, CRITICAL-tier tools are allowed
            (subject to escalation). When ``False`` (default), CRITICAL
            tools are always blocked.
        allow_unregistered: When ``True``, tools not in the registry are
            allowed (dangerous; useful only during dev). Defaults to
            ``False``.
    """

    name = "tool_call_inspector"
    stage = Stage.COMMITMENT

    registry: dict[str, ToolSpec] = field(default_factory=dict)
    max_allowed_tier: RiskTier = RiskTier.HIGH
    escalate_at_tier: RiskTier = RiskTier.HIGH
    allow_critical: bool = False
    allow_unregistered: bool = False

    async def inspect_tool_call(self, ctx: ToolCallContext) -> CheckResult:
        spec = self.registry.get(ctx.tool_name)
        if spec is None:
            if self.allow_unregistered:
                return CheckResult.allow(
                    f"unregistered tool {ctx.tool_name!r} allowed by config",
                    tool=ctx.tool_name,
                )
            return CheckResult.block(
                f"tool {ctx.tool_name!r} not in registry",
                tool=ctx.tool_name,
                hint="add a ToolSpec to the registry, or set allow_unregistered=True",
            )

        if spec.risk_tier == RiskTier.CRITICAL and not self.allow_critical:
            return CheckResult.block(
                f"tool {ctx.tool_name!r} is CRITICAL tier and allow_critical=False",
                tool=ctx.tool_name,
                tier=spec.risk_tier.name,
            )

        if spec.risk_tier > self.max_allowed_tier:
            return CheckResult.block(
                f"tool {ctx.tool_name!r} tier {spec.risk_tier.name} exceeds max "
                f"{self.max_allowed_tier.name}",
                tool=ctx.tool_name,
                tier=spec.risk_tier.name,
            )

        if spec.irreversible and spec.risk_tier >= self.escalate_at_tier:
            return CheckResult.escalate(
                f"tool {ctx.tool_name!r} is irreversible and tier "
                f"{spec.risk_tier.name} >= escalate-at {self.escalate_at_tier.name}",
                tool=ctx.tool_name,
                tier=spec.risk_tier.name,
                dryrun_supported=spec.dryrun_supported,
            )

        return CheckResult.allow(
            f"tool {ctx.tool_name!r} cleared (tier={spec.risk_tier.name})",
            tool=ctx.tool_name,
            tier=spec.risk_tier.name,
        )
