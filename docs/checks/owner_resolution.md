# OwnerResolutionCheck

## What it does

Refuses any request that doesn't have a resolvable commit owner. This is the load-bearing check — signet's whole architectural premise is that every action attributable to *someone*. A request without an owner is a request whose audit row reads "unknown caller did unknown thing," which defeats the audit chain's purpose.

## Stage

`ADMISSION` — runs before the request is forwarded upstream.

## How owner resolution works

The check tries headers in this precedence:

1. `X-Commit-Owner: human:<principal>` → `Owner.human(principal)`
2. `X-Agent-Id: agent:<id>` (or bare `<id>`) → `Owner.agent(id)`
3. `X-Policy-Name: <name>` (+ optional `X-Policy-Version`) → `Owner.policy(name@version)`
4. Already-resolved owner on the context (e.g. set by `LoopbackTrustCheck`)

If all four miss:

- `require_owner=True` (default): block with reason `"no commit owner could be resolved"`. The proxy returns HTTP 403.
- `require_owner=False`: fall back to `Owner.policy("unattributed")` and audit a warning. Use only during enforcement shakedowns.

## Configuration

```python
from signet.checks import OwnerResolutionCheck

# Strict (recommended; default)
OwnerResolutionCheck()

# Permissive — for traffic-pattern observation before turning enforcement on
OwnerResolutionCheck(require_owner=False)
```

## Header conventions

| Header | Example | Owner type |
|---|---|---|
| `X-Commit-Owner` | `human:alice@example.com` | human |
| `X-Agent-Id` | `agent:nightly-syncer` | agent |
| `X-Policy-Name` | `acme.security` | policy |
| `X-Policy-Version` | `v3` | (combined with name) |

## Internal callers

If your services are co-located with signet (Rolling Memory, Smart Router, MCP, internal tools), put `LoopbackTrustCheck` *before* `OwnerResolutionCheck` in the pipeline. The loopback check auto-resolves owner for trusted IP ranges (loopback + Tailscale CGNAT) so internal traffic doesn't need to know about the header convention.

## Audit row example

When this check blocks:

```json
{
  "owner_type": "unresolved",
  "owner_id": "",
  "approval_chain": [],
  "check_name": "owner_resolution",
  "decision": "block",
  "reason": "no commit owner could be resolved",
  "metadata": {
    "_check_name": "owner_resolution",
    "_stage": "admission",
    "hint": "set X-Commit-Owner: human:<principal>, ..."
  }
}
```

When it allows:

```json
{
  "owner_type": "human",
  "owner_id": "alice@example.com",
  "approval_chain": ["human:alice@example.com"],
  "check_name": "owner_resolution",
  "decision": "allow",
  "reason": "owner resolved: human:alice@example.com",
  "metadata": {
    "source": "human:alice@example.com"
  }
}
```

## Common bypass attempts (and why they fail)

| Attempt | Result |
|---|---|
| Omit the header entirely | `Decision.BLOCK` (no header → no resolution) |
| Send `X-Commit-Owner: alice` (missing prefix) | `Decision.BLOCK` (precedence requires `human:`) |
| Send `X-Commit-Owner: ""` | `Decision.BLOCK` (empty value) |
| Spoof `X-Commit-Owner: human:admin` | Allowed — but **the audit row records "admin" as the owner**. Spoofing doesn't help an attacker because they're now on the hook for the audit. The check is about attribution, not identity verification. Pair with auth at the network or platform layer. |

This last point is important: signet's owner resolution is **attribution**, not **authentication**. A platform-layer auth gate (mTLS, OIDC, IAM) decides whether the caller's claim of being `human:alice` is true. signet's job is to refuse anything where there's no claim at all.
