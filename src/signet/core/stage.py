"""Stage -- the four-tier check hierarchy.

Every :class:`signet.core.check.Check` declares which stage it runs in. The
:class:`signet.core.pipeline.Pipeline` orders execution by stage, then by
registration order within a stage. Stages fail closed: a block at stage *N*
short-circuits stages *N+1...M*.

The four stages map onto the lifecycle of a single request:

============= =============================================================
Stage         When it runs
============= =============================================================
:attr:`ADMISSION`   Before the request is forwarded upstream. Owner
                    resolution, classification gates, rate limits, prompt
                    injection scans. The request never reaches the model
                    if any ADMISSION check blocks.

:attr:`INSPECTION`  As streamed chunks arrive from the model. Output
                    spillage scanners, scope-drift checks (the "continuing
                    consent" pattern -- the model still has authority to
                    keep generating what it's now generating), live
                    redactors. Block here aborts the stream mid-flight.

:attr:`COMMITMENT`  When the model emits a tool call. Tool-allowlist,
                    risk-tier gating, sandbox preview, dual-human approval
                    for destructive actions. Block here prevents the tool
                    from running.

:attr:`RECORD`      After the response completes. Audit-only checks: drift
                    detection, behavioral baseline updates, metrics. A
                    block here does NOT modify the already-delivered
                    response -- it is recorded in the audit chain only,
                    typically for incident response and trend analysis.
============= =============================================================

Why a four-stage hierarchy and not a flat list:

1. **Cost ordering.** ADMISSION checks are cheap and many; INSPECTION
   checks fire on every chunk and must be fast; COMMITMENT checks may
   call out to sandboxes; RECORD checks can be expensive because they
   are off the critical path. Splitting them lets each stage have its
   own performance budget.

2. **Failure semantics.** ADMISSION blocks return 403 to the caller.
   INSPECTION blocks truncate the stream and emit a trailing event.
   COMMITMENT blocks refuse the tool but allow the model to continue.
   RECORD blocks never affect the caller. The pipeline knows the right
   action per stage.

3. **Re-evaluation.** The "continuing consent" pattern lives at
   INSPECTION -- even though the request was admitted, the gate
   re-checks authority on what the model is actually producing.
"""

from __future__ import annotations

import enum


class Stage(enum.StrEnum):
    """The four stages of signet's check hierarchy.

    Order matters: lower-ordinal stages run first, and a block at any stage
    short-circuits all later stages.
    """

    ADMISSION = "admission"
    """Pre-request: decide whether the request enters the system at all."""

    INSPECTION = "inspection"
    """Mid-stream: continuously re-evaluate as the model produces output."""

    COMMITMENT = "commitment"
    """Per tool-call: decide whether a proposed side-effecting action runs."""

    RECORD = "record"
    """Post-response: audit-only; never modifies the already-delivered output."""

    @property
    def ordinal(self) -> int:
        """Numeric position in the lifecycle (0..3). Used for pipeline ordering."""
        return _STAGE_ORDER[self]


_STAGE_ORDER: dict[Stage, int] = {
    Stage.ADMISSION: 0,
    Stage.INSPECTION: 1,
    Stage.COMMITMENT: 2,
    Stage.RECORD: 3,
}
