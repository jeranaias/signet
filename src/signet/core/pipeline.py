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
import time
from collections.abc import Awaitable, Iterable
from typing import Protocol

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext, ToolCallContext
from signet.core.stage import Stage


class _HistogramObserver(Protocol):
    """Structural type for the metrics dependency the pipeline needs.

    Matches :meth:`signet.server.metrics.Metrics.observe_histogram`.
    Defined as a Protocol (rather than importing ``Metrics`` directly)
    so ``signet.core`` keeps no hard dependency on ``signet.server`` —
    the pipeline must be usable in CLI tools, tests, and embedded apps
    without dragging the whole HTTP stack in.
    """

    def observe_histogram(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None: ...


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

    def __init__(
        self,
        checks: Iterable[Check],
        *,
        metrics: _HistogramObserver | None = None,
    ) -> None:
        # Sort by stage ordinal first, then by check.priority within a
        # stage. Python's stable sort preserves registration order on
        # priority ties, so the historical "registration order is
        # respected" contract still holds for any check that doesn't
        # set its own priority.
        self._checks: list[Check] = sorted(
            checks, key=lambda c: (c.stage.ordinal, getattr(c, "priority", 0))
        )
        # ``metrics`` is optional so Pipeline stays usable in tests,
        # CLI tools, and embedded contexts that don't run the HTTP
        # server. When unset, the per-check duration histogram simply
        # isn't emitted — observers see nothing rather than a partial
        # signal that could mislead alerting.
        self._metrics: _HistogramObserver | None = metrics

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
            result = await self._dispatch(check, "pre_request", check.pre_request(ctx))
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
            result = await self._dispatch(
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
            result = await self._dispatch(check, "inspect_tool_call", check.inspect_tool_call(ctx))
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
            result = await self._dispatch(check, "post_complete", check.post_complete(ctx))
            results.append(_annotate(result, check))
        return results

    async def _dispatch(
        self, check: Check, hook_name: str, coro: Awaitable[CheckResult]
    ) -> CheckResult:
        """Run a single check hook, honoring its timeout and emitting timing.

        Single point of dispatch for every hook so the per-check latency
        histogram is observed exactly once per invocation, regardless of
        which hook fired or whether the call timed out. Timeouts map to
        ``decision="block"`` (fail-closed) so the histogram surfaces
        slow checks even when they exceed their budget.
        """
        start = time.perf_counter()
        result = await _run_with_timeout(check, hook_name, coro)
        if self._metrics is not None:
            elapsed = time.perf_counter() - start
            decision_label = _decision_label(result)
            self._metrics.observe_histogram(
                "signet_check_duration_seconds",
                elapsed,
                {
                    "check": check.name,
                    "stage": check.stage.value,
                    "decision": decision_label,
                },
            )
        return result


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


def _decision_label(result: CheckResult) -> str:
    """Map a CheckResult to a stable string label for metrics.

    Mirrors the four-way Decision split used elsewhere (allow / block /
    redact / escalate). Anything unrecognized is mapped to ``block`` so
    a future Decision variant doesn't quietly disappear from the
    histogram — fail-closed labelling, same posture as
    :func:`signet.server.app._result_to_decision`.
    """
    if result.is_allow:
        return "allow"
    if result.is_block:
        return "block"
    if result.is_redact:
        return "redact"
    if result.is_escalate:
        return "escalate"
    return "block"


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
