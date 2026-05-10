"""LoopbackTrustCheck -- auto-resolve owner for trusted internal IPs.

Co-located services (background workers, internal admin tools, sidecars)
typically don't carry a per-request commit-owner header. They should not
have to. signet's loopback-trust check sits *before*
:class:`signet.checks.owner_resolution.OwnerResolutionCheck` and
auto-assigns a ``policy:internal-loopback`` or ``policy:internal-tailnet``
owner when the request originates from a trusted address range.

This avoids the "every internal call now 403s" failure mode that
naively turning on owner enforcement in production produces. External
callers still must supply explicit headers; only network neighbors get
the trust.

Configurable trust ranges:

* Loopback (``127.0.0.0/8`` and ``::1``) -- always trusted by default.
* Tailscale CGNAT (``100.64.0.0/10``) -- trusted by default; turn off
  for environments not on Tailscale.
* Custom CIDR ranges -- pass ``extra_trusted_cidrs`` to extend.

When trust matches, the resolved owner records the actual source IP so
audits can still attribute to a specific machine, just under a policy
ownership umbrella. Example: ``policy:internal-tailnet:100.90.15.26``.
"""

from __future__ import annotations

import ipaddress

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.owner import Owner
from signet.core.stage import Stage


class LoopbackTrustCheck(Check):
    """Auto-resolve owner for trusted internal IPs."""

    name = "loopback_trust"
    stage = Stage.ADMISSION

    DEFAULT_LOOPBACK_NETS: tuple[str, ...] = ("127.0.0.0/8", "::1/128")
    """IPv4 loopback and IPv6 loopback address ranges."""

    DEFAULT_TAILSCALE_CGNAT: str = "100.64.0.0/10"
    """RFC 6598 CGNAT block, used by Tailscale and some other overlay
    networks. Distinct from RFC 1918 private ranges."""

    def __init__(
        self,
        *,
        trust_loopback: bool = True,
        trust_tailscale: bool = True,
        extra_trusted_cidrs: tuple[str, ...] = (),
    ) -> None:
        """
        Args:
            trust_loopback: Trust 127.0.0.0/8 and ::1.
            trust_tailscale: Trust the RFC 6598 CGNAT block 100.64.0.0/10.
            extra_trusted_cidrs: Additional CIDR ranges to trust. Each is
                parsed via :mod:`ipaddress`; supply v4 or v6 freely.
        """
        cidrs: list[str] = []
        if trust_loopback:
            cidrs.extend(self.DEFAULT_LOOPBACK_NETS)
        if trust_tailscale:
            cidrs.append(self.DEFAULT_TAILSCALE_CGNAT)
        cidrs.extend(extra_trusted_cidrs)

        self._networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
            ipaddress.ip_network(c) for c in cidrs
        )

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        # If owner is already resolved, we're not the one to override it.
        if ctx.owner.is_resolved:
            return CheckResult.allow()

        if not ctx.client_ip:
            return CheckResult.allow()  # no IP to evaluate; defer

        try:
            ip = ipaddress.ip_address(ctx.client_ip)
        except ValueError:
            return CheckResult.allow()  # malformed; defer to next check

        for net in self._networks:
            if ip in net:
                policy_id = self._policy_id_for(ip, net)
                ctx.owner = Owner.policy(policy_id)
                return CheckResult.allow(
                    f"trusted source {ip}; resolved to policy:{policy_id}",
                    matched_network=str(net),
                )

        return CheckResult.allow()  # not trusted; let later checks decide

    def _policy_id_for(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> str:
        """Generate a descriptive policy ID embedding the source IP."""
        if ip.is_loopback:
            return "internal-loopback"
        if str(net) == self.DEFAULT_TAILSCALE_CGNAT:
            return f"internal-tailnet:{ip}"
        return f"internal-trusted:{ip}"
