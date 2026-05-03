![signet](.github/banner-placeholder.svg)

# signet

> Capability-based safety gates for LLM agents. The model proposes; signet authorizes.

**signet** sits between an LLM and any system that can execute its outputs. It is a small set of programmatic checks — owner resolution, classification gating, dual-judge dissent, sandbox preview, HMAC-chained audit — that decide whether the model's proposed action is allowed to actually run.

The model never holds commit authority. Same shape as a junior employee who can fill out a purchase order but cannot sign the check.

## Why this exists

LLM agents that "wait for human input" rely on the model itself to comply with the instruction. Sufficiently capable models ignore the instruction whenever their objective gradient outweighs it. No prompt fixes that.

signet takes a different path: separate **deciding what to do** from **being allowed to do it**. The model decides; signet decides whether the decision can fire. The model's compliance is no longer load-bearing for the gate.

## Install

```bash
pip install signet-py
```

## Quickstart — drop-in OpenAI-compatible proxy

Run the proxy in front of any OpenAI-compatible upstream:

```bash
signet serve --upstream https://api.openai.com/v1 --port 8443
```

Point your client at `http://localhost:8443/v1` and add an owner header:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8443/v1",
    default_headers={"X-Commit-Owner": "human:alice@example.com"},
)
client.chat.completions.create(model="gpt-4o", messages=[...])
```

Without `X-Commit-Owner` (or `X-Agent-Id`, or a configured trusted-network fallback), the proxy returns `403 Pyros owner-resolution refusal` and writes an audit row.

## Architecture in one paragraph

A `Pipeline` runs an ordered list of `Check` objects against every request. Each check can `pre_request` (block before forward), `inspect_response_chunk` (abort mid-stream), `inspect_tool_call` (block tool execution), or `post_complete` (audit). All decisions are written to an HMAC-chained, tamper-evident audit log (NIST 800-53 AU-3 / AU-9 compatible).

See [`docs/architecture.md`](docs/architecture.md) for the full design.

## Built-in checks

| Check | What it does |
|---|---|
| `owner_resolution` | Refuse requests without resolvable commit owner |
| `hmac_audit` | Append every decision to the tamper-evident chain |
| `rate_limit` | Token-bucket per owner |
| `regex_content` | Block / redact patterns in input or output |
| `classification_gate` | 5-level architectural enforcement (UNCLASS → TS/SCI) |
| `prompt_injection` | Pattern + heuristic scan |
| `tool_call_inspector` | Inspect tool calls before forwarding |
| `token_budget` | Per-owner token quotas |
| `loopback_trust` | Auto-resolve owner for trusted internal IPs |

Bring your own via the plugin interface — [`docs/plugin_dev.md`](docs/plugin_dev.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Provenance

Built by Jesse Morgan in tandem with Thornveil. Thornveil makes no IP claim on this open-source release; it is contributed under Apache-2.0 for community use. The proprietary Pyros engine and Mycelium proof-of-inference layer remain separate; signet is the publishable subset of the architectural pattern.
