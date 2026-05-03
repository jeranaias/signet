# RegexContentCheck / RegexOutputCheck

## What they do

Pattern-based scanners that block or redact specific strings.
Two flavors:

- `RegexContentCheck` — runs at **ADMISSION**, scans the *request*
  body. Typical use: refuse requests that look like they contain
  PII, secrets the model shouldn't see, or domain-banned terms.
- `RegexOutputCheck` — runs at **INSPECTION**, scans the streaming
  *response* body. Typical use: catch the model leaking a marker
  string, an API key it hallucinated, or any pattern you don't want
  the caller to see.

Both share the same matcher; the difference is *when* they fire and
what they do on match.

## Stage

- `RegexContentCheck`: `ADMISSION`.
- `RegexOutputCheck`: `INSPECTION`.

## Configuration

```python
from signet.checks import RegexContentCheck, RegexOutputCheck, Pattern

# Block requests containing US SSN-shaped strings
RegexContentCheck(patterns=[
    Pattern(
        regex=r"\b\d{3}-\d{2}-\d{4}\b",
        action="block",
        label="ssn",
        replacement="[REDACTED-SSN]",   # ignored when action="block"
    ),
])

# Redact instead — let the request through with the pattern replaced
RegexContentCheck(patterns=[
    Pattern(
        regex=r"\b\d{3}-\d{2}-\d{4}\b",
        action="redact",
        label="ssn",
        replacement="[REDACTED-SSN]",
    ),
])

# Output-side: abort streams that contain "SECRET//NOFORN" markers
RegexOutputCheck(patterns=[
    Pattern(regex=r"SECRET//NOFORN", action="block", label="classification-marker"),
])
```

## REDACT vs BLOCK semantics

| Action | What signet does |
|---|---|
| `block` | Refuse the request with HTTP 403 (or abort the stream for output). Audit row records `decision=block`. |
| `redact` | Modify the request body so the matched span is replaced with `replacement`, then forward. Audit row records `decision=redact` with the rule label. |

For **multimodal vision-style content** (`content` is a list of
parts), redact replaces only the text parts; image/audio parts pass
through untouched.

## Audit row example

Block:

```json
{
  "check_name": "regex_content",
  "decision": "block",
  "reason": "pattern 'ssn' matched in request",
  "metadata": {"label": "ssn"}
}
```

Redact:

```json
{
  "check_name": "regex_content",
  "decision": "redact",
  "reason": "pattern 'ssn' redacted in request",
  "metadata": {"label": "ssn", "match_count": 2}
}
```

## What this check is for (and what it's not)

- ✓ Sharp, well-defined patterns — credit card formats, SSN-shaped
  strings, internal classification markers, API key prefixes.
- ✗ Comprehensive PII detection. Use Microsoft Presidio, custom NER,
  or a vendor product as a plugin.
- ✗ Sophisticated content moderation. Layer an LLM-judge plugin at
  COMMITMENT.

The point is *cheap, deterministic, regex-fast* gating for the cases
where you know what you're looking for.
