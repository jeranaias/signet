# ClassificationGateCheck

## What it does

5-level architectural enforcement of the standard US-government classification ladder. The gate refuses if `caller_clearance < data_classification`.

## Stage

`ADMISSION` — runs before the request is forwarded upstream.

## The ladder

| Level | Ordinal | Aliases accepted |
|---|---|---|
| `UNCLASS` | 0 | UNCLASSIFIED, U |
| `CUI` | 1 | FOUO (legacy) |
| `SECRET` | 2 | S |
| `TS` | 3 | TOP SECRET, TOPSECRET |
| `TS/SCI` | 4 | TS-SCI, TS_SCI, SCI |

Comparison is total: `SECRET >= CUI`, `TS/SCI >= TS`, etc. Higher ordinal = more sensitive.

## Headers

| Header | Purpose |
|---|---|
| `X-Classification` | Data classification this request operates on |
| `X-Caller-Clearance` | Caller's asserted clearance level |

Both default to `UNCLASS` when absent.

## Configuration

```python
from signet.checks import ClassificationGateCheck, ClassificationLevel

# Defaults — UNCLASS / UNCLASS, US-gov ladder
ClassificationGateCheck()

# Customize default classification when header is absent
ClassificationGateCheck(default_classification=ClassificationLevel.SECRET)

# Customize header names (rare)
ClassificationGateCheck(
    classification_header="X-Data-Tier",
    clearance_header="X-Caller-Tier",
)
```

For non-government hierarchies (corporate confidential / restricted / public, or healthcare PHI / PII / public), construct with your own enum or remap aliases — see source for the alias table.

## Decision matrix

| Data | Caller UNCLASS | Caller CUI | Caller SECRET | Caller TS | Caller TS/SCI |
|---|---|---|---|---|---|
| UNCLASS | ✓ | ✓ | ✓ | ✓ | ✓ |
| CUI | ✗ | ✓ | ✓ | ✓ | ✓ |
| SECRET | ✗ | ✗ | ✓ | ✓ | ✓ |
| TS | ✗ | ✗ | ✗ | ✓ | ✓ |
| TS/SCI | ✗ | ✗ | ✗ | ✗ | ✓ |

✗ = HTTP 403, audit row recorded with reason `"caller clearance X insufficient for data classification Y"`.

## Pair with ScopeDriftCheck

ADMISSION-stage classification checks the *declared* level. The model can still try to *produce* output above the declared level — leaking SECRET marker strings into a UNCLASS response. `ScopeDriftCheck` at INSPECTION stage catches this case: it scans the accumulated output for classification markers and aborts the stream when one above the request's declared level appears.

Recommended pair:

```python
pipeline = Pipeline(checks=[
    OwnerResolutionCheck(),
    ClassificationGateCheck(),       # ADMISSION: refuse SECRET request from UNCLASS caller
    ScopeDriftCheck(),               # INSPECTION: refuse SECRET output for UNCLASS request
    # ...
])
```

## Common bypass attempts (and why they fail)

| Attempt | Result |
|---|---|
| Omit headers | Both default to UNCLASS → allowed for UNCLASS data |
| Spoof `X-Caller-Clearance: TS/SCI` | Allowed — but **identity is on the audit row**. Like owner resolution, this is enforcement layered on top of platform auth. |
| Send `X-Classification: SEEKRET` | `Decision.BLOCK` ("unrecognized classification header value") — no fuzzy matching |
| Send mixed-case `X-CLASSIFICATION: secret` | Headers and values are case-insensitive; same as `X-Classification: SECRET` |

## Audit row example

Block:

```json
{
  "check_name": "classification_gate",
  "decision": "block",
  "reason": "caller clearance UNCLASS insufficient for data classification SECRET",
  "metadata": {
    "classification": "SECRET",
    "clearance": "UNCLASS"
  }
}
```

Allow:

```json
{
  "check_name": "classification_gate",
  "decision": "allow",
  "reason": "clearance TS cleared for SECRET",
  "metadata": {
    "classification": "SECRET",
    "clearance": "TS"
  }
}
```
