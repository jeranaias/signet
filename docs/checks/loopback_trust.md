# LoopbackTrustCheck

## What it does

Auto-resolves the commit owner for requests originating from
trusted internal IP ranges — loopback (`127.0.0.0/8`, `::1`) and
Tailscale CGNAT (`100.64.0.0/10`) by default. Lets internal services
co-located with signet (Rolling Memory, an internal MCP, your own
gateway) skip the `X-Commit-Owner` header dance for trusted traffic
without disabling owner enforcement for external callers.

Useful pattern: stack `LoopbackTrustCheck` *before*
[`OwnerResolutionCheck`](owner_resolution.md). Loopback traffic
auto-resolves to `policy:internal-loopback`; OwnerResolutionCheck
sees `ctx.owner.is_resolved` and passes through.

## Stage

`ADMISSION` — runs before any forwarding decision.

## Configuration

```python
from signet.checks import LoopbackTrustCheck

# Defaults (loopback + Tailscale CGNAT)
LoopbackTrustCheck()

# Add additional trusted CIDRs (your own VPC range, Wireguard subnet, etc.)
LoopbackTrustCheck(extra_trusted_cidrs=("10.42.0.0/16", "fd7a:115c::/48"))
```

The default trusted set:

| CIDR | Purpose |
|---|---|
| `127.0.0.0/8` | IPv4 loopback |
| `::1/128` | IPv6 loopback |
| `100.64.0.0/10` | RFC 6598 (Tailscale CGNAT range) |

## Owner assignment

| Source IP | Resolved owner |
|---|---|
| `127.0.0.1` (loopback) | `policy:internal-loopback` |
| `100.x.y.z` (Tailscale CGNAT) | `policy:internal-tailnet:100.x.y.z` |
| Your `extra_trusted_cidrs` | `policy:internal-loopback` (same as loopback) |
| Anything else | not resolved (next check runs) |

## Audit row example

When loopback traffic resolves:

```json
{
  "owner_type": "policy",
  "owner_id": "internal-loopback",
  "approval_chain": ["policy:internal-loopback"],
  "check_name": "loopback_trust",
  "decision": "allow",
  "reason": "loopback IP resolved to policy:internal-loopback"
}
```

## Caveat

This check **trusts the source IP**. If your reverse proxy doesn't
strip / overwrite a forwarded-for header that signet might mistake for
the real source, an external caller could spoof their way into the
trusted range. Make sure your reverse proxy sets the source IP signet
sees to the *actual* peer, not whatever the caller claims.
