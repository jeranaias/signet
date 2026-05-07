"""SandboxPreviewCheck — preview tool calls before they commit.

For irreversible tools (file deletion, payments, external API mutations),
running the call in a sandbox first to *preview* the effect lets the
gate audit the simulated outcome and decide whether to commit the real
call.

This reference plugin defers the actual sandboxing to a caller-supplied
async runner. signet's value here is the *gating discipline* — when to
preview, what to do with the preview output, how to chain into a real
commit — not the sandbox implementation itself. Bring your own.

Typical runner shape::

    async def my_runner(tool_name: str, arguments: dict) -> SandboxResult:
        # Run the tool in a Docker container, sandboxed VM, or
        # capability-limited subprocess.
        # Return what would happen without committing.
        ...

The check then evaluates the :class:`SandboxResult` against a policy
predicate also supplied by the caller. Default policy: any result that
:meth:`SandboxResult.is_safe` returns True for is allowed; anything else
escalates for human review.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from signet.core.check import Check, CheckResult
from signet.core.context import ToolCallContext
from signet.core.stage import Stage

logger = logging.getLogger("signet.plugins.sandbox")


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """The outcome of a preview run.

    Attributes:
        ok: Whether the simulated execution completed without error.
        observed_effect: Free-form description of what the tool would
            have done. Used by the policy predicate.
        details: Implementation-specific structured detail (file paths
            written, API calls made, side effects observed).
    """

    ok: bool
    observed_effect: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def is_safe(self) -> bool:
        """Heuristic safety predicate. **Treat as a placeholder.**

        Returns True iff the preview ran without error AND none of a
        small built-in keyword list (``destroy``, ``delete``,
        ``irreversible``, ``payment``, ``transfer``) appears in
        ``observed_effect``. The list is deliberately tiny: false
        positives on any benign description containing the word
        "delete"; false negatives on synonyms (``purge``, ``wire``,
        ``void``, ``remove``) and on non-English effect descriptions.

        For real use, do NOT rely on this. Pass a custom ``policy=``
        callable to :class:`SandboxPreviewCheck` that inspects the
        structured ``details`` field instead of grep-matching prose.
        """
        if not self.ok:
            return False
        flag_words = ("destroy", "delete", "irreversible", "payment", "transfer")
        return not any(w in self.observed_effect.lower() for w in flag_words)


#: Caller-supplied preview runner.
SandboxRunner = Callable[[str, dict[str, Any]], Awaitable[SandboxResult]]

#: Caller-supplied policy predicate. Receives the preview result and
#: returns True to commit, False to escalate.
SandboxPolicy = Callable[[SandboxResult], bool]


def _default_policy(result: SandboxResult) -> bool:
    return result.is_safe()


@dataclass
class SandboxPreviewCheck(Check):
    """Run a tool through a caller-supplied sandbox before committing.

    Args:
        runner: Async function that takes ``(tool_name, arguments)``
            and returns a :class:`SandboxResult` describing what the
            tool would do.
        policy: Predicate over :class:`SandboxResult` deciding allow
            (True) vs escalate (False). Defaults to
            ``SandboxResult.is_safe``.
        only_for_tools: When non-empty, only run sandbox preview for
            tools in this set. Empty (default) means preview every
            tool that reaches this check.
        require_dryrun_supported: When ``True`` (default), a tool whose
            registry metadata reports ``dryrun_supported=False`` is
            *escalated* immediately rather than previewed. Prevents
            silently skipping the preview for tools that can't actually
            be previewed.
        registry: Optional shared
            ``dict[str, signet.checks.tool_call_inspector.ToolSpec]``.
            When provided, this check reads ``dryrun_supported`` (and
            other tool fields) from the registry, treating it as the
            canonical source rather than relying on
            ``ToolCallContext.tool_metadata`` being populated separately.
            Pass the **same** dict you handed to
            :class:`signet.checks.tool_call_inspector.ToolCallInspectorCheck`
            so the two checks agree. When not provided, falls back to
            ``ctx.tool_metadata`` (the v0.1.4 behavior).
    """

    name = "sandbox_preview"
    stage = Stage.COMMITMENT

    runner: SandboxRunner = field(default=None)  # type: ignore[assignment]
    policy: SandboxPolicy = _default_policy
    only_for_tools: frozenset[str] = field(default_factory=frozenset)
    require_dryrun_supported: bool = True
    registry: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.runner is None:
            raise ValueError("SandboxPreviewCheck requires a `runner` callable")

    async def inspect_tool_call(self, ctx: ToolCallContext) -> CheckResult:
        if self.only_for_tools and ctx.tool_name not in self.only_for_tools:
            return CheckResult.allow(
                f"sandbox skipped (tool {ctx.tool_name!r} not in only_for_tools)"
            )

        if self.require_dryrun_supported:
            dryrun_ok = self._lookup_dryrun_supported(ctx)
            if not dryrun_ok:
                return CheckResult.escalate(
                    f"tool {ctx.tool_name!r} cannot be sandbox-previewed; escalating",
                    tool=ctx.tool_name,
                )

        try:
            result = await self.runner(ctx.tool_name, ctx.arguments)
        except Exception as exc:
            logger.warning(
                "sandbox runner failed for %s: %s: %s",
                ctx.tool_name,
                type(exc).__name__,
                exc,
            )
            return CheckResult.block(
                f"sandbox runner raised {type(exc).__name__}: {exc}; failing closed",
                tool=ctx.tool_name,
            )

        if self.policy(result):
            return CheckResult.allow(
                f"sandbox preview ok: {result.observed_effect[:80]}",
                tool=ctx.tool_name,
                preview_ok=result.ok,
            )
        return CheckResult.escalate(
            f"sandbox preview flagged: {result.observed_effect[:80]}",
            tool=ctx.tool_name,
            preview_ok=result.ok,
            details=result.details,
        )

    def _lookup_dryrun_supported(self, ctx: ToolCallContext) -> bool:
        """Resolve the dryrun_supported flag from the canonical source.

        When :attr:`registry` is set, the matching :class:`ToolSpec`
        wins (the single-source-of-truth path). Otherwise fall back to
        ``ctx.tool_metadata["dryrun_supported"]`` (the v0.1.4 path, kept
        for backwards compatibility with callers that hand-populate
        tool metadata).
        """
        if self.registry is not None and ctx.tool_name in self.registry:
            spec = self.registry[ctx.tool_name]
            return bool(getattr(spec, "dryrun_supported", False))
        return bool(ctx.tool_metadata.get("dryrun_supported", False))


__all__ = ["SandboxPolicy", "SandboxPreviewCheck", "SandboxResult", "SandboxRunner"]
