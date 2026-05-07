"""OwnerResolutionCheck — refuse if no commit owner can be resolved.

This is the load-bearing check. signet's whole architectural premise is
that every action must be attributable to an accountable owner. If a
request arrives without one and no fallback resolves one, the gate
refuses before the model ever sees the request.

Resolution precedence (first match wins, deterministic regardless of
header order on the wire):

1. Already-resolved :class:`Owner` on the context (e.g. populated by
   :class:`signet.checks.loopback_trust.LoopbackTrustCheck` or another
   resolver running earlier in the pipeline). Skips header parsing.
2. ``X-Commit-Owner: human:<principal>`` — direct human assertion.
3. ``X-Agent-Id: agent:<id>`` — autonomous-agent assertion.
4. ``X-Policy-Name`` + optional ``X-Policy-Version`` — a named
   organizational policy delegating authority.

When all four miss, the check returns ``Decision.BLOCK`` with reason
``"no commit owner could be resolved"``. The proxy translates this to
HTTP 403 with the reason in the response body. If a request supplies
both ``X-Commit-Owner`` and ``X-Agent-Id``, the human assertion wins;
the agent header is ignored without warning. To override, drop the
human header at your reverse-proxy layer.

Header lookup is case-insensitive (HTTP headers are case-insensitive
on the wire; many ASGI servers preserve incoming case). All values are
stripped of leading/trailing whitespace before matching.

Caveat: signet does NOT authenticate these headers. The audit row
records "the caller said X"; it does not prove X is the caller. See
``SECURITY.md`` and ``docs/architecture.md`` trust-model section.

Strict mode is the default and recommended setting. Permissive mode
(``require_owner=False``) instead resolves the unresolved case to
``policy:unattributed`` — useful only for non-production observability
shakedowns where you want to see traffic patterns before turning
enforcement on.

The ``require_owner=True`` ↔ :attr:`OwnerType.UNRESOLVED` flow,
end-to-end::

    # 1. Proxy receives a POST with no commit-owner headers.
    # 2. Pipeline builds a RequestContext with owner=Owner.unresolved().
    # 3. OwnerResolutionCheck.pre_request runs first in ADMISSION:
    #      - ctx.owner.is_resolved is False
    #      - no header matches the resolution precedence
    #      - require_owner=True → returns CheckResult.block(...)
    # 4. Proxy turns the BLOCK into HTTP 403 with body
    #    {"error": "refused", "correlation_id": "<entry>"}    (strict)
    #    or {"error": "...", "reason": "no commit owner...", ...}  (--dev)
    # 5. The audit row pins owner=unresolved with the firing check name.
"""

from __future__ import annotations

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.owner import Owner
from signet.core.stage import Stage

# Canonical header names. Lookup is case-insensitive — see _get_header.
_HEADER_COMMIT_OWNER = "X-Commit-Owner"
_HEADER_AGENT_ID = "X-Agent-Id"
_HEADER_POLICY_NAME = "X-Policy-Name"
_HEADER_POLICY_VERSION = "X-Policy-Version"


def _get_header(headers: dict[str, str], name: str) -> str:
    """Case-insensitive single-header lookup; returns ``""`` when absent.

    HTTP headers are case-insensitive but Python dicts are not. Some
    ASGI servers normalize to lowercase, others preserve the case the
    client sent. We try the canonical case first (cheapest), then walk
    the dict with a case-fold compare.
    """
    v = headers.get(name)
    if v:
        return v.strip()
    target = name.lower()
    for k, val in headers.items():
        if k.lower() == target and val:
            return val.strip()
    return ""


class OwnerResolutionCheck(Check):
    """Resolve and require a commit owner before forwarding."""

    name = "owner_resolution"
    stage = Stage.ADMISSION

    def __init__(self, *, require_owner: bool = True) -> None:
        """
        Args:
            require_owner: When ``True`` (default), block requests with no
                resolvable owner. When ``False``, fall back to
                ``policy:unattributed`` and audit a warning. Set ``False``
                only during enforcement shakedowns.
        """
        self.require_owner = require_owner

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        # If a previous resolver already set a real owner, accept it.
        if ctx.owner.is_resolved:
            return CheckResult.allow(
                f"owner already resolved: {ctx.owner}",
                source="upstream-resolver",
            )

        resolved = self._resolve_from_headers(ctx.headers)
        if resolved is not None:
            ctx.owner = resolved
            return CheckResult.allow(
                f"owner resolved: {resolved}",
                source=resolved.approval_chain[0] if resolved.approval_chain else "headers",
            )

        if self.require_owner:
            return CheckResult.block(
                "no commit owner could be resolved",
                hint=(
                    "Send one of these headers (the prefix is required):\n"
                    "  X-Commit-Owner: human:alice@example.com\n"
                    "  X-Agent-Id: agent:nightly-syncer\n"
                    "  X-Policy-Name: acme-default   (with optional X-Policy-Version: v3)\n"
                    "Headers are caller-asserted attribution, not authentication — "
                    "see SECURITY.md trust model."
                ),
                examples=[
                    "X-Commit-Owner: human:alice@example.com",
                    "X-Agent-Id: agent:nightly-syncer",
                    "X-Policy-Name: acme-default",
                ],
            )

        # Permissive fallback: assume an unattributed policy
        ctx.owner = Owner.policy("unattributed")
        return CheckResult.allow("permissive fallback to policy:unattributed")

    @staticmethod
    def _resolve_from_headers(headers: dict[str, str]) -> Owner | None:
        # Precedence: human > agent > policy. If two are sent the human
        # claim wins and the others are silently dropped — documented in
        # the module docstring.
        co = _get_header(headers, _HEADER_COMMIT_OWNER)
        if co.startswith("human:"):
            principal = co[len("human:") :]
            if principal:
                return Owner.human(principal)

        ai = _get_header(headers, _HEADER_AGENT_ID)
        if ai.startswith("agent:"):
            agent_id = ai[len("agent:") :]
            if agent_id:
                return Owner.agent(agent_id)
        # Bare X-Agent-Id values without the agent: prefix are NOT accepted.
        # The prefix is required for symmetry with X-Commit-Owner: human:<id>
        # and so an attacker can't bypass owner resolution by sending an
        # arbitrary string in X-Agent-Id.

        pn = _get_header(headers, _HEADER_POLICY_NAME)
        if pn:
            pv = _get_header(headers, _HEADER_POLICY_VERSION)
            # Policy name + version are joined with a literal '@'. If
            # your policy name contains '@', supply the joined form
            # yourself in X-Policy-Name and leave X-Policy-Version unset.
            return Owner.policy(f"{pn}@{pv}" if pv else pn)

        return None
