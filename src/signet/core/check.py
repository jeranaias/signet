"""Check — the policy-evaluation primitive.

A :class:`Check` inspects some aspect of a request, response, or tool call and
produces a :class:`CheckResult` saying *allow*, *block*, *redact*, or
*escalate*. Checks are the building blocks: a :class:`Pipeline` runs a list of
them in order against every request.

Checks have four optional hook points, each of which defaults to a permissive
no-op. Subclasses override only the hooks they care about:

============================ ================================================
Hook                          When the pipeline calls it
============================ ================================================
:meth:`pre_request`           Before the request is forwarded to the upstream.
                              Block here to refuse without ever consulting
                              the model.
:meth:`inspect_response_chunk` On every streamed chunk. Block here to abort
                              mid-stream — important for spillage detection.
:meth:`inspect_tool_call`     When the model emits a tool call. Block here to
                              prevent execution of a specific tool invocation.
:meth:`post_complete`         After the response has finished. Used by audit
                              and metric checks that need the full transcript.
============================ ================================================

Hooks are async because real-world checks frequently call out to other
services (LLM judges, sandbox runners, classifier endpoints). Synchronous
checks just don't ``await`` anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from signet.core.audit import Decision
from signet.core.stage import Stage

if TYPE_CHECKING:
    from signet.core.context import RequestContext, ResponseContext, ToolCallContext


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The outcome of a single check evaluation.

    Attributes:
        decision: What the pipeline should do with the request.
        reason: Human-readable rationale, ideally short and policy-tagged.
            Surfaces in audit rows and 4xx response bodies.
        metadata: Free-form structured detail attached to the audit row when
            this result is recorded. Use sparingly.
        replacement_content: When ``decision`` is :attr:`Decision.REDACT`,
            the content that should replace the original. ``None`` for any
            other decision.
    """

    decision: Decision
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    replacement_content: str | None = None

    @classmethod
    def allow(cls, reason: str = "", **metadata: Any) -> CheckResult:
        """Convenience constructor for an allow result."""
        return cls(decision=Decision.ALLOW, reason=reason, metadata=metadata)

    @classmethod
    def block(cls, reason: str, **metadata: Any) -> CheckResult:
        """Convenience constructor for a block result."""
        return cls(decision=Decision.BLOCK, reason=reason, metadata=metadata)

    @classmethod
    def redact(cls, replacement: str, reason: str, **metadata: Any) -> CheckResult:
        """Convenience constructor for a redact result. The ``replacement``
        becomes the new content that flows downstream."""
        return cls(
            decision=Decision.REDACT,
            reason=reason,
            metadata=metadata,
            replacement_content=replacement,
        )

    @classmethod
    def escalate(cls, reason: str, **metadata: Any) -> CheckResult:
        """Convenience constructor for an escalate result. The pipeline will
        suspend the request pending out-of-band human approval."""
        return cls(decision=Decision.ESCALATE, reason=reason, metadata=metadata)

    @property
    def is_allow(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def is_block(self) -> bool:
        return self.decision is Decision.BLOCK

    @property
    def is_redact(self) -> bool:
        return self.decision is Decision.REDACT

    @property
    def is_escalate(self) -> bool:
        return self.decision is Decision.ESCALATE


class Check:
    """Base class for all checks.

    Subclasses must override :attr:`name` and :attr:`stage`. They override
    the hooks they care about; unimplemented hooks return a permissive
    ``CheckResult.allow()``. The class is not formally ``ABC`` because its
    hooks have permissive defaults rather than abstract methods, but the
    ``__init_subclass__`` validator enforces the same "you must declare
    these" contract.

    A check instance is reused across many requests; do not stash per-request
    state on ``self``. If you need it, use the ``RequestContext.scratch`` dict
    or carry it through the metadata field of intermediate results.
    """

    name: str = ""
    """Stable identifier for this check; surfaces in audit rows and metrics.
    Subclasses MUST set this to a non-empty value."""

    stage: Stage = Stage.ADMISSION
    """Which lifecycle stage this check runs in. The pipeline orders checks
    by stage; within a stage, registration order is preserved. Subclasses
    SHOULD override to declare their stage explicitly even when ADMISSION
    is correct, to make intent obvious."""

    timeout_seconds: float | None = None
    """Maximum wall-clock time the pipeline waits for any single hook on
    this check. ``None`` (default) means no timeout; the pipeline waits
    indefinitely. When set and exceeded, the pipeline treats the check
    as having returned ``CheckResult.block(...)`` with a timeout reason —
    fail-closed semantics. Set per-check to bound external dependencies
    (LLM-judge calls, sandbox runners) so a stuck dependency cannot
    halt the proxy."""

    priority: int = 0
    """Sub-ordering within a stage. Lower runs earlier, ties preserve
    registration order. Defaults to ``0``. The pipeline still groups by
    :class:`Stage` first; ``priority`` only matters between two checks
    that share a stage. Use to enforce dependencies — e.g.
    :class:`signet.checks.rate_limit.RateLimitCheck` declares
    ``priority=100`` so it runs after content-scanning ADMISSION checks
    and a refused request never costs a token. Set ``priority < 0`` to
    force a check earlier than the default cohort."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "name", None):
            raise TypeError(
                f"Check subclass {cls.__name__!r} must set a non-empty `name` class attribute"
            )
        if not isinstance(getattr(cls, "stage", None), Stage):
            raise TypeError(
                f"Check subclass {cls.__name__!r} must set `stage` to a Stage enum value"
            )

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        """Called before the request is forwarded upstream.

        Default: allow. Override to add a check that should run before any
        model invocation (owner resolution, rate limit, classification gate,
        prompt injection scan, etc.).
        """
        return CheckResult.allow()

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        """Called on every streamed response chunk.

        Default: allow. Override for spillage detection, output content
        filtering, mid-stream abort. Returning :attr:`Decision.BLOCK` aborts
        the stream immediately and the caller receives a truncated response
        with a trailer indicating which check fired.
        """
        return CheckResult.allow()

    async def inspect_tool_call(self, ctx: ToolCallContext) -> CheckResult:
        """Called when the model emits a tool call, before that tool runs.

        Default: allow. Override to block specific tools, require sandbox
        preview for destructive ones, or escalate to dual-human approval.
        """
        return CheckResult.allow()

    async def post_complete(self, ctx: ResponseContext) -> CheckResult:
        """Called after the full response has been delivered.

        Default: allow. Override for audit-only checks, metrics emission,
        retroactive flagging, drift detection, or behavioral baselines.
        Returning a non-allow decision at this hook does NOT modify the
        already-delivered response; it is recorded in the audit chain only.
        """
        return CheckResult.allow()
