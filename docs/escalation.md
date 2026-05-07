# Escalation flow (COMMITMENT stage)

When a tool call requires out-of-band approval, signet's COMMITMENT stage
returns a `CheckResult.escalate(...)`. The proxy translates this to HTTP
202 Accepted (or to `X-Signet-Shadow-Decision: escalate` in shadow mode).

The audit row carries the routing information needed to drive an
approval workflow:

* `metadata.requires_approval_from` — full ordered approval chain.
* `metadata.current_approver` — first link, the next person whose action
  is needed.
* `metadata.tool_name` — what the model proposed.
* `metadata.risk_tier`, `metadata.irreversible` — why escalation fired.

## Worked example

```python
from signet.core.owner import Owner, OwnerType

owner = Owner(
    owner_type=OwnerType.HUMAN,
    owner_id="jesse@thornveil",
    approval_chain=("manager@thornveil", "ceo@thornveil"),
)
```

When `jesse@thornveil` issues a request through the proxy and a HIGH-tier
irreversible tool call fires, the escalation audit row contains:

```json
{
  "decision": "escalate",
  "metadata": {
    "tool_name": "send_email",
    "risk_tier": "HIGH",
    "irreversible": true,
    "requires_approval_from": ["manager@thornveil", "ceo@thornveil"],
    "current_approver": "manager@thornveil",
    "_check_name": "tool_call_inspector",
    "_stage": "commitment"
  }
}
```

## What signet does and doesn't do

* **Does**: surface routing metadata. Audit row is the source of truth
  for any approval workflow.
* **Doesn't (in 0.1.6)**: drive the approval workflow itself. There is
  no `signet escalation` subcommand yet, no webhook config, no auto-deny
  policy. Build those on top — your approval system reads escalation
  audit rows, asks the current approver out-of-band, and re-issues the
  request when approved.
* **Roadmap (0.1.7)**: `signet escalation pending|approve|deny`,
  multi-step chain walking, timeout policy.

## Multi-step chains

In 0.1.6, `current_approver` is always the first link of `approval_chain`.
Chain walking (advance to next link after the first approves) is roadmap.
For now, your approval workflow does the walking — when approver N
approves, your system re-issues the request with `approval_chain[1:]`
(approver N stripped).
