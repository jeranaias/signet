"""ContinuingConsentCheck — re-evaluate owner authority mid-stream.

Authority granted at the start of a request is not a blank check for
the entire stream. Conditions can change while the model is generating:

* The owner's session might be revoked by an external system mid-stream.
* The owner's clearance might be downgraded.
* A rate limit might tip into block on a different request that arrived
  in parallel.
* An external policy oracle (LDAP, SSO, an HRIS) might rule that the
  owner is no longer authorized.

This check periodically re-runs an owner-authority predicate during
INSPECTION. When the predicate flips from "ok" to "no", the stream is
aborted and the caller is told the gate withdrew consent mid-flight.

The predicate is caller-supplied: pass an async function ``revalidate``
that takes the current :class:`signet.core.context.ResponseContext` and
returns ``True`` if the owner still has consent, ``False`` if not. The
check throttles invocations via ``check_every_chunks`` to avoid
hammering the predicate on every chunk.

For the common case where revalidation just re-checks an in-process
flag or cache, the throttle can be set low (every 1-3 chunks). For
remote revalidation (LDAP query, oracle call), use larger throttles
(every 10+ chunks) and accept some latency in detection.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from signet.core.check import Check, CheckResult
from signet.core.context import ResponseContext
from signet.core.stage import Stage

#: A revalidation predicate. Returns True when consent stands; False to
#: revoke and abort the stream.
RevalidateFn = Callable[[ResponseContext], Awaitable[bool]]


async def _always_consenting(_ctx: ResponseContext) -> bool:
    """Default predicate: always True. Effectively a no-op until the
    caller wires in a real revalidator."""
    return True


@dataclass
class ContinuingConsentCheck(Check):
    """INSPECTION-stage check: revoke mid-stream when consent is withdrawn.

    Args:
        revalidate: Async predicate that returns ``True`` while consent
            stands and ``False`` when it should be withdrawn. Defaults
            to a no-op that always returns True; supply your own to
            integrate with session/SSO/policy systems.
        check_every_chunks: Throttle invocations. The predicate runs on
            chunks 1, 1+N, 1+2N, ... where N is this value. Defaults
            to 5; lower means tighter detection at higher cost; higher
            means cheaper at the cost of detection latency.
        revocation_reason: Human-readable reason recorded when consent
            is withdrawn. Defaults to a generic message; supply your
            own for context-specific guidance.
    """

    name = "continuing_consent"
    stage = Stage.INSPECTION

    revalidate: RevalidateFn = _always_consenting
    check_every_chunks: int = 5
    revocation_reason: str = "owner consent withdrawn during stream"

    def __post_init__(self) -> None:
        if self.check_every_chunks < 1:
            raise ValueError("check_every_chunks must be >= 1")

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        # Throttle: only revalidate on every Nth chunk to keep cost down.
        if ctx.chunk_count % self.check_every_chunks != 1:
            return CheckResult.allow()

        try:
            still_ok = await self.revalidate(ctx)
        except Exception as exc:
            # Predicate errors fail closed: revoke rather than risk a
            # silent allow on a misconfigured check.
            return CheckResult.block(
                f"continuing-consent revalidator raised {type(exc).__name__}: {exc}; "
                f"failing closed",
                error_class=type(exc).__name__,
                error_message=str(exc),
            )

        if not still_ok:
            return CheckResult.block(
                self.revocation_reason,
                chunks_consumed=ctx.chunk_count,
                accumulated_chars=len(ctx.accumulated_text),
            )

        return CheckResult.allow(
            "continuing consent verified",
            chunks_consumed=ctx.chunk_count,
        )
