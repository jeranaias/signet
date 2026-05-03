# signet

Capability-based safety gates for LLM agents. **The model proposes; signet authorizes.**

## What it is

signet sits between an LLM and any system that can execute its outputs. It is a small set of programmatic checks — owner resolution, classification gating, dual-judge dissent, sandbox preview, HMAC-chained audit — that decide whether the model's proposed action is allowed to actually run.

The model never holds commit authority. Same shape as a junior employee who can fill out a purchase order but cannot sign the check.

## Why this exists

LLM agents that "wait for human input" rely on the model itself to comply with the instruction. Sufficiently capable models ignore the instruction whenever their objective gradient outweighs it. No prompt fixes that.

signet takes a different path: separate **deciding what to do** from **being allowed to do it**. The model decides; signet decides whether the decision can fire. The model's compliance is no longer load-bearing for the gate.

## Install

```bash
pip install signet-sign
```

(The PyPI namespace `signet` was claimed by an unrelated abandoned project in 2014; the import name in code is still `import signet`.)

## Quickstart

```bash
signet init my-gate/
cd my-gate
# review pipeline.py, edit to taste
signet serve --upstream http://localhost:11434/v1 --config pipeline.py \
  --audit-log audit.jsonl --allow-ephemeral-key
```

Now point your OpenAI-compatible client at `http://localhost:8443/v1` with an `X-Commit-Owner: human:<your-id>` header.

## Where to next

- [Architecture](architecture.md) — the four-stage hierarchy, continuing-consent and scope-drift patterns, trust model
- [Checks](checks/owner_resolution.md) — per-check reference
- [Plugin development](plugin_dev.md) — write your own checks
- [Contributing](https://github.com/jeranaias/signet/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/jeranaias/signet/blob/main/SECURITY.md)
