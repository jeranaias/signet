# ContinuingConsentCheck

## What it does

Periodic mid-stream owner-authority revalidation. ADMISSION lets a
request through with a snapshot of the owner's authority; that
authority can change *during* a long-running stream (session
expired, owner clearance downgraded, user signed out elsewhere).
ContinuingConsentCheck calls a caller-supplied predicate every N
chunks during INSPECTION. If the predicate ever returns `False`,
the stream is aborted.

## Stage

`INSPECTION`.

## Configuration

```python
from signet.checks import ContinuingConsentCheck
from signet.core.context import ResponseContext


async def revalidate_owner(ctx: ResponseContext) -> bool:
    """Return True iff this owner still has authority to receive output.

    Called every check_every_chunks of streaming. Anything that can
    change mid-stream goes here: SSO session lookups, IdP token
    revocation checks, IdM group membership recheck, policy oracles.
    """
    owner = ctx.request.owner
    # Example: re-query your IdP to see if the session is still valid
    return await my_idp.session_active(owner.owner_id)


ContinuingConsentCheck(
    revalidate=revalidate_owner,
    check_every_chunks=10,           # check every 10 streamed chunks
    revalidation_timeout_seconds=2.0, # fail-closed if predicate hangs
)
```

## When this matters

Long-running streaming responses (LLM completions of any
substantial length) take seconds-to-minutes. Authority that was
valid at request-admission time can be revoked during the stream
— and without continuing-consent, the gate keeps streaming
content the owner is no longer authorized to receive.

Concrete scenarios:

- User clicks "log out" in another tab → IdP invalidates the
  session → continuing-consent's IdP query returns False → stream
  aborts.
- Security operations marks a token compromised mid-incident →
  next continuing-consent check returns False → all streams
  using that token terminate.
- An owner's clearance level is downgraded by HR → next check
  returns False if their request implied a level they no longer
  hold.

Without this check, all of the above leak content from
admission-time-good to revocation-time-bad with no signal.

## Audit row example

```json
{
  "check_name": "continuing_consent",
  "decision": "block",
  "reason": "owner consent withdrawn at chunk 47",
  "metadata": {
    "owner": "human:alice@example.com",
    "checks_performed": 5,
    "chunks_at_revocation": 47
  }
}
```

## Predicate guidance

- **Make it fast.** This runs every N chunks; even at N=10, a slow
  predicate adds noticeable latency. Aim for <100ms p99.
- **Cache aggressively.** The predicate is allowed to return based
  on cached state; freshness is a tradeoff between accuracy and
  cost. A 30-second TTL on session-active lookups is reasonable.
- **Fail-closed on errors.** The default `revalidation_timeout_seconds`
  is 2.0 — predicates that hang or raise are treated as a `False`
  return and abort the stream. The audit row notes the predicate
  exception.
- **Don't reach for `ctx.request.body`.** That's the original
  request as admitted; if you need the *latest* user state, look
  it up via the owner identity, not via reading the body.
