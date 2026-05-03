# ToolCallInspectorCheck

## What it does

COMMITMENT-stage gate for every tool call the model wants to
execute. Each tool is registered with a `ToolSpec` declaring its
risk tier and whether the action is irreversible. The check decides
per-call:

- **Allow**: tool is on the allowlist, risk tier permitted.
- **Block**: tool is unknown, or risk tier above ceiling.
- **Escalate** (HTTP 202): tool is irreversible AND risk tier ≥
  the escalation threshold. Caller must obtain out-of-band human
  approval and resubmit.

The point: the model proposes any tool call it likes; signet
decides whether each call gets to fire. Same shape as a junior
employee filling out the purchase order while the CFO signs the
check.

## Stage

`COMMITMENT`.

## Configuration

```python
from signet.checks import ToolCallInspectorCheck, ToolSpec, RiskTier

ToolCallInspectorCheck(
    registry={
        # Reads — low risk
        "list_files": ToolSpec(risk_tier=RiskTier.LOW),
        "read_file": ToolSpec(risk_tier=RiskTier.LOW),

        # Mutations — medium risk
        "write_file": ToolSpec(risk_tier=RiskTier.MEDIUM),

        # Irreversible — escalate
        "send_email": ToolSpec(
            risk_tier=RiskTier.HIGH,
            irreversible=True,
            dryrun_supported=False,
        ),
        "process_payment": ToolSpec(
            risk_tier=RiskTier.CRITICAL,
            irreversible=True,
            dryrun_supported=True,
        ),
    },
    max_allowed_tier=RiskTier.HIGH,    # CRITICAL is opt-in only
    allow_critical=False,
    escalation_threshold=RiskTier.HIGH, # HIGH+irreversible escalates
)
```

### Risk tiers

| Tier | Numeric | Typical examples |
|---|---|---|
| `LOW` | 0 | Read-only operations, idempotent lookups |
| `MEDIUM` | 1 | Internal mutations, state changes that can be undone |
| `HIGH` | 2 | External-facing actions, communications, file writes |
| `CRITICAL` | 3 | Payments, deletes, anything with regulatory weight |

### Irreversibility flag

`irreversible=True` triggers the escalation logic at or above the
escalation threshold. Examples that should be marked irreversible:

- Sending email/SMS/messages (you can't unsend)
- Issuing payments / refunds (financial commitment)
- Deleting data (rollback is best-effort)
- Calls to external APIs with side effects

`dryrun_supported=True` is informational metadata used by the
[`SandboxPreviewCheck`](../plugin_dev.md) reference plugin — it
hints the tool can be safely simulated before commit.

### Allowlist semantics

Tools NOT in the registry default to BLOCK. Set
`allow_unregistered=True` to flip this (not recommended — implicit
allowlists are how scope creep happens).

## Audit row examples

Block (unknown tool):

```json
{
  "check_name": "tool_call_inspector",
  "decision": "block",
  "reason": "tool 'rm_rf' not in registry",
  "metadata": {"tool": "rm_rf"}
}
```

Block (above ceiling):

```json
{
  "check_name": "tool_call_inspector",
  "decision": "block",
  "reason": "tool 'process_payment' tier CRITICAL exceeds max_allowed_tier HIGH",
  "metadata": {"tool": "process_payment", "tier": "CRITICAL"}
}
```

Escalate:

```json
{
  "check_name": "tool_call_inspector",
  "decision": "escalate",
  "reason": "tool 'send_email' is irreversible (HIGH); requires human approval",
  "metadata": {
    "tool": "send_email",
    "tier": "HIGH",
    "audit_entry_id": "abc123-..."
  }
}
```

The proxy translates ESCALATE to HTTP 202 Accepted with the
`audit_entry_id` so the caller can poll / wait / re-submit after
out-of-band approval.

## Pair with sandbox preview

For the strongest "preview before commit" semantics, pair this
check with [`SandboxPreviewCheck`](../plugin_dev.md). The flow:

1. ToolCallInspectorCheck → BLOCK or ESCALATE for irreversible tools.
2. Caller's escalation system runs the tool in `mode=preview` via
   the sandbox runner.
3. The simulated effect goes through the same audit pipeline.
4. Only on human approval does the real call fire.

Production-tuned dual-judge calibration + classification-aware
sandbox isolation are typical engagements for vendors maintaining
that infrastructure.
