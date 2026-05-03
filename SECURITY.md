# Security policy

## Reporting a vulnerability

**Do not open a public GitHub issue.** Email jeranaias@gmail.com with:

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

### Read this first — what the audit log actually proves

Two limits worth understanding before you build on signet:

1. **Owner identity is caller-asserted, not authenticated.** The
   `X-Commit-Owner` / `X-Agent-Id` / `X-Policy-Name` headers are taken
   at face value. signet does not verify a JWT, OIDC token, mTLS
   client cert, or SSO session. Every audit row records *what the
   caller said the owner was* — useful for accountability inside a
   trust boundary you already control, **not** as proof of identity
   to a third party. Layer real authentication (mTLS, OIDC,
   `LoopbackTrustCheck` over a tailnet) at or before signet's
   ADMISSION stage if your threat model needs it.

2. **The HMAC chain is tamper-evident, not tamper-proof.** It detects
   modification of any subset of entries when verified by a party
   that holds the same key. It does **not** prevent rewriting: an
   attacker with file-write access to the audit log AND the HMAC
   secret can replace the entire chain with a freshly-signed one and
   the verifier sees no break. True append-only / tamper-proof needs
   one of: WORM storage (S3 Object Lock, immutable filesystem),
   external anchoring (RFC 3161 timestamp authority, Sigstore Rekor,
   transparency log), or witnessed publication of recent HMACs to a
   party the attacker cannot reach. Roadmapped for v0.2 via a
   pluggable anchor backend; not in v0.1.

signet defends against:

- **An LLM ignoring "stop and wait" instructions.** The pipeline runs out-of-process; the model's compliance is not load-bearing.
- **Unattributable requests** (within the assumption above): owner resolution refuses requests with no resolvable commit owner before the model is consulted.
- **Output spillage above declared classification.** ScopeDriftCheck aborts streams whose content drifts above the request's `X-Classification`.
- **Tamper of post-hoc audit logs by parties without the HMAC key.** HMAC chain detects modify, delete, reorder, and forged-insert tampering.
- **Off-path commits.** Adversarial test suite asserts that every routed handler writes an audit entry.
- **Race-induced chain corruption from in-process concurrent writers.** `HmacChain.append` holds an internal lock; the FastAPI event loop cannot fork the chain by interleaving two appends.

signet does **not** defend against:

- A compromised proxy host. The HMAC key lives on disk; a host-level attacker can rewrite the chain end-to-end and re-sign.
- **Receipt forgery by a verifier.** The built-in `HmacReceiptSigner` is symmetric — anyone who can verify a receipt holds the secret to forge one. Acceptable when the verifier is in your trust domain; not acceptable for handing receipts to outside parties. Asymmetric (ed25519) signers are roadmapped for v0.2.
- **Multi-process audit writers.** Running `uvicorn --workers N>1` gives each worker an independent lock and an independent `_cached_prev`; concurrent appends across workers can fork the chain. Run with one worker, or implement a backend that takes a cross-process file lock.
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

## Supply chain

Every published release attaches a CycloneDX SBOM (`signet-sbom.cdx.json`) generated from the build environment to the corresponding GitHub Release. Use it to audit transitive dependencies without reproducing the build.

Roadmapped for v0.2:

- Sigstore-signed releases (`cosign` attestation against the artifact).
- SLSA Level 3 build provenance via the GitHub OIDC reusable workflow.
- Reproducible-build instructions.

Until then, verify install integrity by comparing the wheel hash on PyPI against the GitHub Release artifact.
