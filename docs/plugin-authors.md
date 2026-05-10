# Plugin authors

signet's check pipeline is open at the edges: third-party plugins
register a Check subclass against a Python entry point and the proxy
discovers them at startup. No fork required, no signet code changes.

## How signet discovers plugins

At process start, signet walks three entry-point groups:

* `signet.checks` — full Check subclasses (the common case).
* `signet.adapters` — drop-in HTTP adapters (OpenAI/Anthropic/LangChain shapes).
* `signet.anchors` — external anchor backends.

For every entry point in those groups, signet attempts `.load()`,
verifies ABI compatibility, and records the result. The CLI's
`signet plugins list` surfaces the full discovery report including
load failures and ABI mismatches so misconfiguration is visible
instead of silent.

## Registering a check

In your plugin package's `pyproject.toml`:

```toml
[project.entry-points."signet.checks"]
geopolitical_compliance = "thornveil_extras.checks:GeopoliticalComplianceCheck"
```

The class on the right must subclass `signet.core.check.Check`. That
gives it the four lifecycle hooks for free:

```python
from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.stage import Stage

class GeopoliticalComplianceCheck(Check):
    name = "geopolitical_compliance"
    stage = Stage.ADMISSION

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        # ... your logic ...
        return CheckResult.allow("ok")
```

Pipelines reference the check by entry-point name:

```python
from signet.plugins import resolve

geo = resolve("geopolitical_compliance")
pipeline = Pipeline(checks=[geo(strict=True), ...])
```

## Duplicate entry-point names

Two packages cannot share an entry-point name in the same group.
If both `pkg-one` and `pkg-two` register
`signet.checks: geopolitical_compliance = ...`, signet's discovery
walk now flags **both** entries as `duplicate_name` rather than
silently picking whichever was installed first. The CLI surfaces
the conflict and `signet.plugins.resolve(...)` raises `RuntimeError`
listing the conflicting packages so the operator knows which one
to uninstall.

This matters most for plugin upgrades: if a vendor renames the
import path but keeps the entry-point name, an old version of the
package left behind in `site-packages` would silently shadow the
new one. Discovery-time detection turns that into a loud failure.

If you need parallel implementations, give them distinct names —
`my_check_v1`, `my_check_v2` — or scope them to a different group.

## ABI versioning

signet exposes `signet.core.check.CHECK_ABI_VERSION` as a stable
contract identifier. Your plugin inherits the default ABI from
`Check.CHECK_ABI_VERSION`. If signet's ABI bumps, your plugin keeps
working until it's loaded by an incompatible signet — at which
point `signet plugins list` reports it as `incompatible_abi` and
the proxy refuses to instantiate it.

## Pinning your dependency

Until signet hits 1.0, pin against minor:

```toml
[project]
dependencies = ["signet-sign~=0.1"]
```

The 0.1.x line is in active design; major-version (X.Y) is the
boundary for ABI compatibility. After 1.0, pin against `~=1.0` and
let patch versions float.

## What's roadmap (not in 0.1.6)

* Hot-reload of plugins without proxy restart.
* Plugin-supplied lint rules (so third parties can extend
  `signet lint`).
* Plugin-supplied report formats (so third parties can extend
  `signet audit report`).
