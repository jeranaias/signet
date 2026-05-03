"""Pipeline — the executor that runs checks against a request.

A :class:`Pipeline` holds an ordered list of :class:`Check` objects and
exposes one method per hook timing. Checks are sorted by
:class:`signet.core.stage.Stage` (lower-ordinal stages first); within a
stage, registration order is preserved. The pipeline is fail-closed: the
first non-allow result short-circuits the rest of the stage and the rest of
the pipeline for the relevant hook.

The pipeline is the only thing in :mod:`signet.core` that knows about
multiple checks at once. Concrete checks live in :mod:`signet.checks`; the
HTTP proxy in :mod:`signet.server` invokes the pipeline at the appropriate
points in request handling.

Per-check timeouts: any check whose ``timeout_seconds`` attribute is set
gets its hook calls wrapped in :func:`asyncio.wait_for`. A timeout is
translated to ``CheckResult.block(...)`` with a timeout reason —
fail-closed, so a stuck external dependency (LLM judge, sandbox runner,
oracle) cannot halt the proxy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Iterable

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext, ToolCallContext
from signet.core.stage import Stage


class Pipeline:
    """Sequenced execution of checks across the four hook timings.

    Construct with an iterable of :class:`Check` instances. The pipeline
    sorts them by stage at construction time so iteration order at hook
    time is stable and cheap.

    Example::

        pipeline = Pipeline(
            checks=[
                OwnerResolutionCheck(require_owner=True),
                ClassificationGateCheck(),
                ContinuingConsentCheck(),
                ScopeDriftCheck(),
            ]
        )

        result = await pipeline.pre_request(ctx)
        if result.is_block:
            return refuse(result.reason)
    """

    def __init__(self, checks: Iterable[Check]) -> None:
        # Sort by stage ordinal then preserve insertion order within stage
        # via Python's stable sort.
        self._checks: list[Check] = sorted(checks, key=lambda c: c.stage.ordinal)

    @property
    def checks(self) -> tuple[Check, ...]:
        """Read-only view of registered checks in execution order."""
        return tuple(self._checks)

    def checks_for_stage(self, stage: Stage) -> tuple[Check, ...]:
        """All checks scheduled for the given stage, in execution order."""
        return tuple(c for c in self._checks if c.stage is stage)

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        """Run every ADMISSION-stage check.

        Returns the first non-allow result, or
        ``CheckResult.allow("admission cleared")`` if all checks pass.
        """
        for check in self.checks_for_stage(Stage.ADMISSION):
            result = await _run_with_timeout(check, "pre_request", check.pre_request(ctx))
            if not result.is_allow:
                return _annotate(result, check)
        return CheckResult.allow("admission cleared")

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        """Run every INSPECTION-stage check against the new chunk.

        Returns the first non-allow result, or
        ``CheckResult.allow()`` if all checks pass. The proxy aborts the
        upstream stream on a non-allow result here.
        """
        for check in self.checks_for_stage(Stage.INSPECTION):
            result = await _run_with_timeout(
                check, "inspect_response_chunk", check.inspect_response_chunk(ctx, chunk)
            )
            if not result.is_allow:
                return _annotate(result, check)
        return CheckResult.allow()

    async def inspect_tool_call(self, ctx: ToolCallContext) -> CheckResult:
        """Run every COMMITMENT-stage check against the proposed tool call.

        Returns the first non-allow result, or
        ``CheckResult.allow("tool call approved")`` if all checks pass.
        """
        for check in self.checks_for_stage(Stage.COMMITMENT):
            result = await _run_with_timeout(
                check, "inspect_tool_call", check.inspect_tool_call(ctx)
            )
            if not result.is_allow:
                return _annotate(result, check)
        return CheckResult.allow("tool call approved")

    async def post_complete(self, ctx: ResponseContext) -> list[CheckResult]:
        """Run every RECORD-stage check.

        Unlike the other hooks, RECORD is *non-short-circuiting*: every
        check runs and every result is returned. RECORD checks are
        audit-only — they cannot modify the already-delivered response —
        so the pipeline collects all of them for the audit chain.
        """
        results: list[CheckResult] = []
        for check in self.checks_for_stage(Stage.RECORD):
            result = await _run_with_timeout(check, "post_complete", check.post_complete(ctx))
            results.append(_annotate(result, check))
        return results


async def _run_with_timeout(
    check: Check, hook_name: str, coro: Awaitable[CheckResult]
) -> CheckResult:
    """Await ``coro`` with the check's timeout (if any), fail-closed on timeout.

    A timeout is translated to ``CheckResult.block(...)`` with a clear
    reason; any other exception bubbles to the proxy, which records a
    pipeline-crash audit row and returns 500.
    """
    timeout = getattr(check, "timeout_seconds", None)
    if timeout is None:
        return await coro
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except TimeoutError:
        return CheckResult.block(
            f"check {check.name!r}.{hook_name} timed out after {timeout}s",
            check=check.name,
            hook=hook_name,
            timeout_seconds=timeout,
        )


def _annotate(result: CheckResult, check: Check) -> CheckResult:
    """Attach the originating check name to a result's metadata.

    Used so audit rows and error responses can identify which check made
    the decision without changing :class:`CheckResult` to carry a back-
    reference (which would couple it to the pipeline).
    """
    if "_check_name" in result.metadata:
        return result
    new_metadata = {**result.metadata, "_check_name": check.name, "_stage": check.stage.value}
    return CheckResult(
        decision=result.decision,
        reason=result.reason,
        metadata=new_metadata,
        replacement_content=result.replacement_content,
    )
