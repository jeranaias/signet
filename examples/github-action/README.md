# GitHub Actions: signet policy + bench check

A CI workflow that gates pull requests on three things:

1. **`signet lint --strict`** -- static analysis of `pipeline.py`.
   Catches the four most common misconfigurations (rate-limit ordering,
   missing owner resolution, open tool registry, classification without
   drift). Strict mode promotes warnings to errors.
2. **`signet doctor --probe-injection`** -- brings signet up against a
   mock upstream and replays an obfuscated prompt-injection corpus.
   Every probe must be refused.
3. **`signet bench --gate p95=10ms,p99=20ms`** -- microbenchmark gate
   against a mock upstream. Refuses PRs that regress p95 past 10 ms or
   p99 past 20 ms.

## Wiring into your repo

1. Copy `.github/workflows/signet-check.yml` to the same path in your
   repo.
2. Make sure `pipeline.py` exists at the repo root (`signet init`
   scaffolds one if you don't have it yet).
3. Push. The workflow runs on any PR that touches `pipeline.py`
   plus the workflow file itself, and on manual `workflow_dispatch`.

## Required secrets

None. The workflow runs entirely with a mock upstream so there are no
API keys or HMAC secrets to provision. The `--dev` flag on `signet
serve` generates an ephemeral HMAC key per run.

If you want to gate on a *real* upstream's behavior (e.g., a staging
LLM), add the upstream URL and any auth headers as secrets and pass
them on the `signet serve` line:

```yaml
env:
  UPSTREAM_URL: ${{ secrets.STAGING_UPSTREAM_URL }}
  UPSTREAM_TOKEN: ${{ secrets.STAGING_UPSTREAM_TOKEN }}
```

## Adjusting the gates

- **p95 / p99 thresholds**: edit the `--gate` argument in the bench
  step. Format is `pN=<duration>` where `N` is an integer percentile
  in 1..99, with `ms` / `s` / `us` (or `μs`) suffixes -- e.g.
  `p50=5ms,p95=10ms,p99=20ms` or `p99=0.02s`. The `--gate` flag accepts
  percentile thresholds only; `mean=` and `max=` are NOT supported and
  will be rejected by the parser.
- **Trigger paths**: by default the workflow only runs when
  `pipeline.py` changes. Add more files (the check registry, custom
  plugins, etc.) under `on.pull_request.paths` if your policy lives in
  more than one place.
- **Python version**: pinned to 3.12 to match the signet test matrix.
  Bump in lockstep with the `requires-python` floor in `pyproject.toml`.

## When the workflow fails

The workflow uploads `signet.log` on failure. Common modes:

- *Lint failure*: read the finding code (`SIGLINT-0xx`) and fix the
  underlying check ordering / config.
- *Probe failure*: a payload made it past `PromptInjectionCheck`. Either
  the rule set was loosened or a new bypass landed; both deserve a
  manual review before merging.
- *Bench failure*: signet got slower. Profile locally with
  `signet bench --mock-upstream --profile` (no gate) and compare to
  `main`.
