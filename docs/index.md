# signet

> **The model decides what to do. signet decides whether the decision is allowed to fire.**

Your AI agents are issuing refunds, calling APIs, running tools, writing to databases. Each of those actions is being authorized by a non-deterministic system that can be talked into anything by a sufficiently clever prompt. **The blast radius of "the model held commit authority" is your next incident report.**

signet is a small Apache-2.0 proxy that sits between your callers and the LLM. Every request runs through programmatic checks before the model sees it; every response is re-checked before the caller sees it; every tool call is gated before it executes. Every decision lands in a tamper-evident, HMAC-chained audit log compatible with NIST 800-53 audit-content and integrity requirements.

**The model never holds commit authority — same shape as a junior employee who fills out the purchase order but can't sign the check.**

Drop-in: existing OpenAI/Anthropic SDK code keeps working with one config change. Runs in your VPC. No data sent to third parties. < 100 MB memory. < 5 ms overhead per request.

## Why this exists

LLMs are non-deterministic software being deployed under deterministic-software governance assumptions. The standard "make the model wait for human approval" pattern depends on the model itself complying with the instruction in its system prompt. Sufficiently capable models ignore that whenever their objective gradient outweighs it. **No prompt fixes that.**

signet takes a different path: separate **deciding what to do** from **being allowed to do it**. The model decides; signet decides whether the decision can fire. The model's compliance is no longer load-bearing for the gate.

## Install

```bash
pip install signet-sign
```

(The PyPI namespace `signet` was claimed by an unrelated abandoned project in 2014; the import name in code is still `import signet`.)

## Quickstart — three commands to a working gate

```bash
signet init my-gate           # scaffold pipeline.py + client_example.py + .env.example + .gitignore
cd my-gate
signet serve --upstream http://localhost:11434/v1 --dev
```

`--dev` bundles `--allow-ephemeral-key`, `--audit-log audit.jsonl`, `--config pipeline.py`, and `--no-strict-error-redaction` so local development is one flag instead of four.

Then point any OpenAI-compatible client at `http://localhost:8443/v1` with an `X-Commit-Owner: human:<your-id>` header. A complete example client lives in the scaffold:

```bash
python client_example.py
```

## Where to next

- [Architecture](architecture.md) — the four-stage hierarchy, continuing-consent and scope-drift patterns, trust model, and what's intentionally out of scope
- [Checks](checks/owner_resolution.md) — per-check reference
- [Plugin development](plugin_dev.md) — write your own checks
- [Contributing](contributing.md)
- [Security policy](security.md) — threat model, reporting, hardening recommendations
- [Changelog](changelog.md)
