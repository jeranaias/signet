"""OwnerResolutionCheck — refuse if no commit owner can be resolved.

This is the load-bearing check. signet's whole architectural premise is
that every action must be attributable to an accountable owner. If a
request arrives without one and no fallback resolves one, the gate
refuses before the model ever sees the request.

Resolution precedence (first match wins):

1. ``X-Commit-Owner: human:<principal>`` header — direct human assertion.
2. ``X-Agent-Id: <agent-id>`` header — autonomous-agent assertion.
3. ``X-Policy-Name`` + optional ``X-Policy-Version`` headers — a named
   organizational policy delegating authority.
4. Already-resolved :class:`Owner` on the context (e.g. populated by
   :class:`signet.checks.loopback_trust.LoopbackTrustCheck` or another
   resolver running earlier in the pipeline).

When all four miss, the check returns ``Decision.BLOCK`` with reason
``"no commit owner could be resolved"``. The proxy translates this to
HTTP 403 with the reason in the response body.

Strict mode is the default and recommended setting. Permissive mode
(``require_owner=False``) instead resolves the unresolved case to
``policy:unattributed`` — useful only for non-production observability
shakedowns where you want to see traffic patterns before turning
enforcement on.
"""

from __future__ import annotations

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.owner import Owner
from signet.core.stage import Stage

# Header names. We accept both the canonical form and a couple of common
# casings — HTTP headers are case-insensitive but Python dicts aren't.
_HEADER_COMMIT_OWNER = ("X-Commit-Owner", "x-commit-owner")
_HEADER_AGENT_ID = ("X-Agent-Id", "X-Agent-ID", "x-agent-id")
_HEADER_POLICY_NAME = ("X-Policy-Name", "x-policy-name")
_HEADER_POLICY_VERSION = ("X-Policy-Version", "x-policy-version")


def _first_header(headers: dict[str, str], names: tuple[str, ...]) -> str:
    """Return the first non-empty header value among ``names``."""
    for n in names:
        v = headers.get(n)
        if v:
            return v
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
                hint="set X-Commit-Owner: human:<principal>, X-Agent-Id: <id>, "
                "or X-Policy-Name: <name> on the request",
            )

        # Permissive fallback: assume an unattributed policy
        ctx.owner = Owner.policy("unattributed")
        return CheckResult.allow("permissive fallback to policy:unattributed")

    @staticmethod
    def _resolve_from_headers(headers: dict[str, str]) -> Owner | None:
        co = _first_header(headers, _HEADER_COMMIT_OWNER)
        if co.startswith("human:"):
            return Owner.human(co[len("human:") :])

        ai = _first_header(headers, _HEADER_AGENT_ID)
        if ai.startswith("agent:"):
            agent_id = ai[len("agent:") :]
            if agent_id:
                return Owner.agent(agent_id)
        # Bare X-Agent-Id values without the agent: prefix are NOT accepted.
        # The prefix is required for symmetry with X-Commit-Owner: human:<id>
        # and so an attacker can't bypass owner resolution by sending an
        # arbitrary string in X-Agent-Id.

        pn = _first_header(headers, _HEADER_POLICY_NAME)
        if pn:
            pv = _first_header(headers, _HEADER_POLICY_VERSION)
            return Owner.policy(f"{pn}@{pv}" if pv else pn)

        return None
