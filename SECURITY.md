# Security policy

## Reporting a vulnerability

**Do not open a public GitHub issue.** Email jesse@thornveil.ai with:

- A description of the issue.
- Steps to reproduce or proof-of-concept.
- Versions of signet affected (if known).
- Whether the issue is currently being exploited or publicly disclosed elsewhere.

Acknowledgement: within 3 business days. Status update: within 10 business days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✓ |
| < 0.1 | ✗ |

Pre-1.0 means the API surface may change in minor versions. Security fixes will be applied to the latest minor only.

## Threat model

signet defends against:

- **An LLM ignoring "stop and wait" instructions.** The pipeline runs out-of-process; the model's compliance is not load-bearing.
- **Unattributable requests.** Owner resolution refuses requests with no resolvable commit owner before the model is consulted.
- **Output spillage above declared classification.** ScopeDriftCheck aborts streams whose content drifts above the request's `X-Classification`.
- **Tamper of post-hoc audit logs.** HMAC chain detects modify, delete, reorder, and forged-insert tampering.
- **Off-path commits.** Adversarial test suite asserts that every routed handler writes an audit entry.

signet does **not** defend against:

- A compromised proxy host. The HMAC key lives on disk; a host-level attacker can rewrite the chain at the head and re-sign.
- A persuasive model talking a tired human into approving a bad action via the escalation path.
- Composed-action drift across many small approved actions adding to one bad outcome (partially mitigated by INSPECTION-stage checks; not fully solved).
- Network-level attacks (use TLS).
- Supply-chain attacks on the model weights themselves.

## Hardening recommendations

For production deployments:

1. Run `signet serve` behind a reverse proxy that terminates TLS.
2. Restrict the bind interface (`--host 127.0.0.1` for sidecar; explicit network for public).
3. Set `SIGNET_HMAC_SECRET` from a secrets manager — never check it into source.
4. Use `--audit-log` on a path that's read-only to other processes.
5. Run the audit verifier nightly via cron: `signet audit verify <log> --hmac-secret <secret>`.
6. Subscribe to releases (https://github.com/jeranaias/signet/releases) so you see security advisories.

## Disclosure policy

We coordinate disclosure with reporters. Default timeline:

1. Acknowledged report.
2. Fix developed in a private fork.
3. Patch released; advisory published with the release notes (CVE assigned if appropriate).
4. Reporter credited (with permission).

We try to ship a patched release before public disclosure unless the issue is already being exploited in the wild.
