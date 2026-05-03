# PromptInjectionCheck

## What it does

Pattern + heuristic scan for prompt-injection attempts in the
request body. Catches the well-known attack families:

- **Override patterns** — "ignore previous instructions",
  "disregard the above", "forget everything you were told"
- **Role spoofing** — `system:`, `assistant:` markers in user
  content; embedded `<|im_start|>` / `<|system|>` chat-template tokens
- **Persona attacks** — DAN, "you are now jailbroken",
  "developer mode enabled", "act as if you have no restrictions"
- **Encoding tricks** — base64 (standard + URL-safe), base32, hex,
  ROT13 blobs that decode to override patterns

## Stage

`ADMISSION`.

## Pre-processing pipeline (v0.1.3+)

Before pattern matching, every input runs through normalization that
defeats the trivial obfuscations a reviewer would reach for first:

1. **NFKC normalization** — collapses compatibility variants
   (full-width letters, ligatures, mathematical alphanumerics) to ASCII.
2. **Confusables fold** — Cyrillic / Greek / Cherokee lookalikes
   mapped to Latin (`іgnore` → `ignore`, `Ｉgnore` → `ignore`).
3. **Zero-width / bidi-formatting strip** — invisible characters
   between visible ones no longer hide patterns.
4. **Stretched-letter collapse** — `i g n o r e` → `ignore`.
5. **Wide encoding decoders** — base64 (standard + URL-safe),
   base32, hex, ROT13 blobs are decoded and the decoded contents
   re-scanned with the same patterns.

Both the original text AND the normalized form are scanned, so
normalization-introduced false negatives are impossible — the raw
input still has the original sensitivity.

## Configuration

```python
from signet.checks import PromptInjectionCheck, Severity

# Defaults: HIGH→block, MEDIUM→escalate, LOW→allow
PromptInjectionCheck()

# Strict: even MEDIUM triggers a block
PromptInjectionCheck(severity_actions={
    Severity.HIGH: "block",
    Severity.MEDIUM: "block",
    Severity.LOW: "escalate",
})

# Permissive: turn HIGH into escalation rather than refusal
PromptInjectionCheck(severity_actions={
    Severity.HIGH: "escalate",
    Severity.MEDIUM: "allow",
    Severity.LOW: "allow",
})
```

## Audit row example

```json
{
  "check_name": "prompt_injection",
  "decision": "block",
  "reason": "matched 'ignore-previous' (HIGH)",
  "metadata": {
    "rule": "ignore-previous",
    "severity": "high",
    "match_source": "decoded-rot13",
    "match_count": 1,
    "all_rules_hit": ["ignore-previous"]
  }
}
```

`match_source` distinguishes the input layer that triggered:
`raw`, `normalized`, `decoded-base64`, `decoded-base64url`,
`decoded-base32`, `decoded-hex`, or `decoded-rot13`. Useful for
post-hoc tuning — if everything is hitting via `decoded-base32`,
your callers may have legitimate base32 use you need to allowlist.

## What this check does NOT catch (genuine ML/data territory)

- **Sophisticated multilingual semantic injection** — attacks
  expressed in Russian/Chinese/Arabic syntax that don't share
  English trigger phrases.
- **Adversarial-suffix attacks** (GCG / AutoDAN-discovered token
  strings). Beyond regex; needs a trained classifier.
- **Multi-step / cross-turn attacks** ("First answer X. Now ignore
  your rules" split across messages or tool-call results).
- **Semantic prompt injection without lexical markers** (rephrased
  attacks that don't use any of the trigger phrases).

For those, layer an LLM-judge plugin at COMMITMENT — see
[`signet.plugins.tribunal`](../plugin_dev.md) for the reference shape.
Production-tuned implementations (calibrated judges, labeled
adversarial corpora, ongoing threat-intel) are typical engagements
for vendors that maintain that data.

## Known false-positive surface

The default rules are tuned to minimize false positives but the
following will trigger:

- Documentation explaining prompt injection (the patterns themselves
  appear in the text).
- Test code that includes attack strings.
- Legitimate user content that happens to contain "ignore previous"
  in non-instruction context.

Tune `severity_actions` to suit your traffic mix, or carve out
allowlist patterns at a higher layer.
