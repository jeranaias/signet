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

C1.4 (v0.1.7): the *value prefix* (``human:`` / ``agent:``) is **case-
sensitive**. ``HUMAN:alice`` and ``Human:alice`` are NOT recognized
and the check will refuse them. The header *name* itself is
case-insensitive — ``x-commit-owner`` and ``X-Commit-Owner`` both
match — but the literal lowercase ``human:`` prefix on the value is
load-bearing. Operators integrating with mixed-case environments
should normalize at the reverse proxy layer.

C1.5 (v0.1.7): when ``X-Policy-Name`` itself contains a literal
``@`` and ``X-Policy-Version`` is also set, the joined form is
``policy:p@ackme@v3`` (double ``@``). This is documented behavior;
the resulting policy ID is ambiguous on round-trip. If your policy
name contains ``@``, supply the joined form yourself in
``X-Policy-Name`` and leave ``X-Policy-Version`` unset.

Caveat: signet does NOT authenticate these headers. The audit row
records "the caller said X"; it does not prove X is the caller. See
``SECURITY.md`` and ``docs/architecture.md`` trust-model section.

Strict mode is the default and recommended setting. Permissive mode
(``require_owner=False``) instead resolves the unresolved case to
``policy:unattributed`` — useful only for non-production observability
shakedowns where you want to see traffic patterns before turning
enforcement on.

The resolved :class:`Owner`'s ``approval_chain`` flows through the
pipeline and is surfaced by the COMMITMENT-stage tool-call inspector
as ``requires_approval_from`` / ``current_approver`` in escalation
audit metadata — see ``docs/escalation.md`` for the routing contract.

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
from signet.core.context import RequestContext, get_header_ci
from signet.core.owner import Owner
from signet.core.stage import Stage

# Canonical header names. Lookup is case-insensitive — see get_header_ci.
_HEADER_COMMIT_OWNER = "X-Commit-Owner"
_HEADER_AGENT_ID = "X-Agent-Id"
_HEADER_POLICY_NAME = "X-Policy-Name"
_HEADER_POLICY_VERSION = "X-Policy-Version"

# Maximum length we accept for any owner / policy principal. Generous
# for legitimate identifiers (UUIDs, fully-qualified emails, agent
# slugs) yet small enough to keep audit-row size bounded against a
# noisy or malicious caller.
_MAX_PRINCIPAL_LEN = 256

# CR / LF / NUL would let a caller forge log lines in any audit
# consumer that splits on newlines (Splunk, Loki, plain ``tail``).
_FORBIDDEN_OWNER_CHARS = frozenset(("\r", "\n", "\x00"))


def _sanitize_principal(value: str) -> str | None:
    """Return a clean principal or ``None`` to signal rejection.

    Rejection cases:

    * empty / whitespace-only after stripping
    * contains CR / LF / NUL (audit-line forgery)
    * contains any other ASCII control character below ``\\x20``
      (regular ASCII space is preserved only in the interior of the
      principal — leading / trailing whitespace is stripped first)
    * exceeds :data:`_MAX_PRINCIPAL_LEN` characters
    """
    if not value:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if len(stripped) > _MAX_PRINCIPAL_LEN:
        return None
    if any(c in _FORBIDDEN_OWNER_CHARS for c in stripped):
        return None
    # Reject any other C0 control characters and DEL (0x7F).
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in stripped):
        return None
    return stripped


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
                    "Send one of these headers. The lowercase prefix is REQUIRED "
                    "and case-sensitive — `HUMAN:alice` and `Human:alice` are NOT "
                    "recognized (C1.4):\n"
                    "  X-Commit-Owner: human:alice@example.com\n"
                    "  X-Agent-Id: agent:nightly-syncer\n"
                    "  X-Policy-Name: acme-default   (with optional X-Policy-Version: v3)\n"
                    "Note: if X-Policy-Name itself contains '@' AND you also set "
                    "X-Policy-Version, the joined form becomes 'policy:name@ver' "
                    "which yields a double-'@' and an ambiguous ID — supply the "
                    "joined form yourself in X-Policy-Name in that case (C1.5).\n"
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
        #
        # All extracted principals are routed through ``_sanitize_principal``
        # to reject CR/LF/NUL, other control chars, and over-length values.
        # On rejection we return None so the ``require_owner=True`` path
        # produces the standard refusal — a forged owner_id never reaches
        # the audit row.
        co = get_header_ci(headers, _HEADER_COMMIT_OWNER)
        if co.startswith("human:"):
            principal = _sanitize_principal(co[len("human:") :])
            if principal:
                return Owner.human(principal)

        ai = get_header_ci(headers, _HEADER_AGENT_ID)
        if ai.startswith("agent:"):
            agent_id = _sanitize_principal(ai[len("agent:") :])
            if agent_id:
                return Owner.agent(agent_id)
        # Bare X-Agent-Id values without the agent: prefix are NOT accepted.
        # The prefix is required for symmetry with X-Commit-Owner: human:<id>
        # and so an attacker can't bypass owner resolution by sending an
        # arbitrary string in X-Agent-Id.

        pn_raw = get_header_ci(headers, _HEADER_POLICY_NAME)
        if pn_raw:
            pn = _sanitize_principal(pn_raw)
            if pn is None:
                return None
            pv_raw = get_header_ci(headers, _HEADER_POLICY_VERSION)
            if pv_raw:
                pv = _sanitize_principal(pv_raw)
                if pv is None:
                    return None
                # Policy name + version are joined with a literal '@'. If
                # your policy name contains '@', supply the joined form
                # yourself in X-Policy-Name and leave X-Policy-Version unset.
                joined = f"{pn}@{pv}"
            else:
                joined = pn
            # Re-cap on the joined form so name+version can't sneak past
            # together what would be rejected individually.
            if len(joined) > _MAX_PRINCIPAL_LEN:
                return None
            return Owner.policy(joined)

        return None
