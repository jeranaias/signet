# TokenBudgetCheck

## What it does

Per-owner cumulative output-token cap over a rolling window.
Distinct from [`RateLimitCheck`](rate_limit.md), which limits
*request count* — `TokenBudgetCheck` limits *total tokens generated*.

Two-stage operation:

- **ADMISSION**: rejects requests whose declared `max_tokens` would
  put the owner over budget when added to their tokens-used-so-far.
- **RECORD**: reads the actual `usage.completion_tokens` from the
  upstream response and reconciles the owner's running total. If
  the actual was less than `max_tokens` (the typical case), the
  unused budget is given back.

This is the right primitive for "alice may use 1M output tokens
per day" or "the trial account may use 10K tokens per hour."

## Stage

`ADMISSION` + `RECORD`.

## Configuration

```python
from signet.checks import TokenBudgetCheck

# Per-day budget of 1M output tokens per owner
TokenBudgetCheck(
    cap=1_000_000,
    window_seconds=86400,
)

# Hourly budget for trial accounts
TokenBudgetCheck(cap=10_000, window_seconds=3600)
```

State backends: same shape as `RateLimitCheck` — in-memory
LRU-bounded by default; supply your own `TokenBudgetState` for
distributed deployments.

## How the budget reconciles

1. ADMISSION reads the request's `max_tokens` (or the model's
   default if unset) and checks whether `used + max_tokens > cap`.
   If yes, refuses with HTTP 403 and a `cap_exceeded` reason.
2. The request is forwarded; the upstream response includes
   `usage.completion_tokens` reporting actual generation.
3. RECORD adjusts the owner's `used` by the *actual* completion
   tokens (not the requested `max_tokens`), so under-asking
   correctly returns the unused portion.
4. Windows are rolling — entries older than `window_seconds` are
   evicted from the sum on every check.

## Audit row example

ADMISSION block:

```json
{
  "check_name": "token_budget",
  "decision": "block",
  "reason": "owner over output-token budget",
  "metadata": {
    "cap": 1000000,
    "window_seconds": 86400,
    "used": 980000,
    "request_max_tokens": 50000,
    "owner": "human:alice@example.com"
  }
}
```

RECORD reconciliation:

```json
{
  "check_name": "token_budget",
  "decision": "allow",
  "reason": "reconciled: requested 50000, used 12480, returned 37520 to budget",
  "metadata": {"cap": 1000000, "window_seconds": 86400, "used": 992480}
}
```

## Caveats

- The cap is per-owner; a single owner with multiple sessions
  shares one bucket. Use distinct owner identities (`human:alice` vs
  `human:bob`) to bucket separately.
- Streaming responses report final usage in the last chunk.
  Mid-stream abort (e.g. by `ScopeDriftCheck`) reconciles partial
  usage at RECORD time so the owner's bucket reflects what was
  actually consumed.
