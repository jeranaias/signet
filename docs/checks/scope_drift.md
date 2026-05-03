# ScopeDriftCheck

## What it does

INSPECTION-stage check that catches three drift categories on
streaming responses:

1. **Token-count drift** — output exceeds `max_tokens × char_per_token_estimate × (1 + tolerance)`.
2. **Character-length drift** — raw output exceeds an absolute character cap.
3. **Classification-marker drift** — output contains a marker
   (e.g. `SECRET//NOFORN`, `(TS)`) that implies a higher
   classification than the request's `X-Classification` declared.

When any drift fires, the stream is aborted mid-flight; the caller
receives the chunks delivered so far plus a trailer event naming the
check. The audit row records exactly which marker / cap fired.

## Stage

`INSPECTION`.

## Configuration

```python
from signet.checks import ScopeDriftCheck

# Defaults: USG marker table, 10% over-shoot tolerance
ScopeDriftCheck()

# Custom marker table for non-USG classification systems
ScopeDriftCheck(markers={
    "INTERNAL_ONLY": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
})

# Disable marker check (token+length drift only)
ScopeDriftCheck(markers={})

# Tighter token-budget tolerance
ScopeDriftCheck(token_tolerance=0.0)  # zero overshoot
```

## Default marker table

```python
{
    # SECRET (level 2)
    "SECRET//NOFORN": 2, "SECRET//REL": 2, "(S)": 2, "(S//NF)": 2,
    # TS / TS/SCI (levels 3-4)
    "TOP SECRET//SCI": 4, "TS//SCI": 4, "(TS)": 3, "(TS//SCI)": 4,
    # CUI (level 1)
    "CUI//": 1, "FOUO": 1,
}
```

Override the entire table via the `markers` constructor argument.

## Audit row example

```json
{
  "check_name": "scope_drift",
  "decision": "block",
  "reason": "classification marker 'SECRET//NOFORN' (level 2) exceeds request level 0 (UNCLASS)",
  "metadata": {
    "marker": "SECRET//NOFORN",
    "marker_level": 2,
    "request_level": 0,
    "drift_kind": "classification_marker"
  }
}
```

For token/length drift:

```json
{
  "check_name": "scope_drift",
  "decision": "block",
  "reason": "output exceeds 200 max_tokens × 4 chars × 1.10 tolerance = 880 chars",
  "metadata": {
    "drift_kind": "token_count",
    "max_tokens": 200,
    "tolerance": 0.10,
    "actual_chars": 942
  }
}
```

## False-positive surface

Marker matching is literal-substring. A model explaining "the
SECRET//NOFORN handling rules are…" in legitimately UNCLASS training
material will trip the check. Mitigations:

- Override the marker table to only include strings your domain
  doesn't use benignly.
- Set `markers={}` to disable classification drift entirely if your
  deployment doesn't use classification.
- Move the check to RECORD-stage (audit-only) for low-stakes
  deployments — drift is logged but doesn't abort the stream.
