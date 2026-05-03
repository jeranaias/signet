"""Context objects passed to :class:`signet.core.check.Check` hooks.

Each hook receives one context object that carries the inputs that hook
needs and a free-form ``scratch`` dict that checks can use to thread state
across calls within a single request.

The context split mirrors the four hook timings:

* :class:`RequestContext` — :meth:`Check.pre_request`
* :class:`ResponseContext` — :meth:`Check.inspect_response_chunk` and
  :meth:`Check.post_complete`
* :class:`ToolCallContext` — :meth:`Check.inspect_tool_call`

These are deliberately simple: dataclasses, mutable, single-request-scoped.
A check that needs richer state should attach it to ``scratch`` or use
:class:`signet.server.session.Session` for cross-request continuity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from signet.core.owner import Owner


@dataclass
class RequestContext:
    """Inputs visible to ADMISSION-stage checks (``pre_request`` hook).

    Attributes:
        owner: The accountable :class:`Owner`. May be unresolved when the
            owner-resolution check itself is running.
        headers: Case-insensitive header dict from the inbound request.
        body: Parsed request body. Typically an OpenAI-shaped chat
            completion request, but the pipeline is agnostic.
        path: The request path (e.g. ``/v1/chat/completions``).
        client_ip: Source IP, used by the loopback-trust check and other
            network-aware policies.
        session_id: Stable session identifier for cross-request state.
            ``None`` when the caller did not assert a session.
        scratch: Free-form dict that checks within this request can use to
            thread state across the four hook timings. Cleared between
            requests.
    """

    owner: Owner
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    path: str = ""
    client_ip: str | None = None
    session_id: str | None = None
    scratch: dict[str, Any] = field(default_factory=dict)


_DEFAULT_ACCUMULATED_TEXT_CAP = 1_048_576  # 1 MiB


@dataclass
class ResponseContext:
    """Inputs visible to INSPECTION and RECORD stage checks.

    A single ``ResponseContext`` instance is reused across the streaming
    lifecycle: each call to :meth:`Check.inspect_response_chunk` sees the
    *same* context with ``accumulated_text`` growing as chunks arrive.
    :meth:`Check.post_complete` sees the same instance with the full text.

    Attributes:
        request: The originating :class:`RequestContext`.
        accumulated_text: All text content seen so far in the stream,
            capped at ``accumulated_text_cap`` bytes (UTF-8). Beyond
            the cap, new content is dropped and ``accumulated_text_truncated``
            is set True. Use :meth:`extend_text` rather than ``+=``
            directly so the cap is enforced without callers having to
            think about it.
        accumulated_text_cap: Maximum size of ``accumulated_text``.
            Default is 1 MiB — enough for INSPECTION-stage checks on
            long completions, while bounded against O(N²) string growth
            on multi-megabyte streams. Adjust if your INSPECTION checks
            need more context, but understand the cost.
        accumulated_text_truncated: True once at least one chunk was
            dropped because the cap was hit. INSPECTION checks should
            treat this as a signal that they're seeing only a prefix.
        chunk_count: Number of chunks delivered so far.
        finish_reason: Set by the proxy when the stream completes
            (``"stop"``, ``"length"``, ``"tool_calls"``, ``"abort"``).
            ``None`` while the stream is in flight.
        usage: OpenAI-shape ``{"prompt_tokens", "completion_tokens",
            "total_tokens"}``. Populated when the upstream returns it,
            either inline or in the final chunk.
        scratch: Free-form dict for cross-hook state within this response.
    """

    request: RequestContext
    accumulated_text: str = ""
    accumulated_text_cap: int = _DEFAULT_ACCUMULATED_TEXT_CAP
    accumulated_text_truncated: bool = False
    chunk_count: int = 0
    finish_reason: str | None = None
    usage: dict[str, int] = field(default_factory=dict)
    scratch: dict[str, Any] = field(default_factory=dict)

    def extend_text(self, more: str) -> None:
        """Append to ``accumulated_text``, enforcing the byte cap.

        Strings, not bytes — the cap is a soft byte budget computed
        against the current length. Once exceeded, additional content
        is dropped and the truncated flag is set; subsequent calls
        become no-ops on the text but still flip the flag for any new
        content received.
        """
        if not more:
            return
        budget = self.accumulated_text_cap - len(self.accumulated_text)
        if budget <= 0:
            self.accumulated_text_truncated = True
            return
        if len(more) > budget:
            self.accumulated_text += more[:budget]
            self.accumulated_text_truncated = True
        else:
            self.accumulated_text += more


@dataclass
class ToolCallContext:
    """Inputs visible to COMMITMENT-stage checks (``inspect_tool_call`` hook).

    The COMMITMENT stage decides per-tool-call whether the proposed action
    is allowed to run. The check sees the tool name, its arguments, and
    metadata that callers can attach to the tool registry (risk tier,
    irreversibility flag, dry-run support).

    Attributes:
        request: The originating :class:`RequestContext`.
        response: The :class:`ResponseContext` accumulated to this point.
        tool_name: The tool the model is asking to invoke.
        arguments: Parsed tool arguments. Shape is tool-specific.
        tool_metadata: Caller-supplied metadata about this tool. Common
            keys: ``"risk_tier"`` (low|medium|high|critical),
            ``"irreversible"`` (bool), ``"dryrun_supported"`` (bool).
        scratch: Free-form dict for state.
    """

    request: RequestContext
    response: ResponseContext
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    tool_metadata: dict[str, Any] = field(default_factory=dict)
    scratch: dict[str, Any] = field(default_factory=dict)
