# `signet bench` -- measure your pipeline overhead

`signet bench` drives synthetic requests through your configured
pipeline and reports the per-request latency signet adds, decomposed
by stage and by check. It exists for one reason: operators evaluating
signet need to verify the "under 5 ms" overhead claim against their
own pipeline.

## What it measures

> **TL;DR.** Pipeline overhead. Not throughput.

For an LLM safety gate, the upstream model call dwarfs every other
component by one to two orders of magnitude. A "100 req/s" claim
would be a claim about the upstream, not about signet. The only
number an operator can move with code changes is the overhead signet
itself adds, so that's the only number `signet bench` measures.

Each synthetic request is driven through the pipeline in-process --
no HTTP, no TCP, no serialization. This isolates signet's own cost.

## Quickstart

```bash
# Smoke test: no upstream, no config, just confirm signet runs.
signet bench --mock-upstream --requests 100 --format markdown

# Real measurement against your pipeline + upstream.
signet bench \
  --upstream http://localhost:11434/v1 \
  --config ./pipeline.py \
  --requests 1000 \
  --concurrency 10

# CI gate: fail the build if p95 regresses past 10 ms.
signet bench --mock-upstream --config ./pipeline.py \
  --requests 1000 --format json --gate p95=10ms,p99=20ms
```

## Reading the report

The markdown report has four sections.

### 1. Setup

What was measured: upstream URL (and its observed latency, if a
baseline ran), the number of checks per stage in the pipeline, the
request count, and the concurrency cap.

### 2. Per-request overhead

Per-stage latency percentiles for the signet pipeline only. The
`TOTAL` row sums the stages. If the `TOTAL` p95 is below your SLO
budget, ship it.

Stages with zero checks render as a clarifying zero row -- a missing
COMMITMENT cost in a run without tool calls is not a measurement bug,
it's the absence of work. The bench surfaces this fact rather than
hiding it.

### 3. End-to-end latency

When `--no-baseline` is not set and an upstream is reachable, this
section compares baseline (direct-to-upstream) latency against
end-to-end latency through signet. The `overhead` row is the absolute
millisecond delta and the relative percentage.

> If your baseline p95 is 400 ms and signet's pipeline p95 is 5 ms,
> the end-to-end overhead is **1.25%**. Operationally invisible.

### 4. Per-check breakdown

One row per check, ranked by stage. `fires` shows how many times the
check ran across the bench window -- a COMMITMENT check on a workload
with no tool calls fires zero times and is annotated as such.

p99 here is the check's tail cost. A single check whose p99 is
20 ms when its p50 is 0.1 ms is a candidate for a per-check
`timeout_seconds` (see `signet.core.check.Check.timeout_seconds`).

## Modes

| Mode                | When to use                                  |
|---------------------|----------------------------------------------|
| Default             | Real upstream, full delta report.            |
| `--no-baseline`     | Upstream is mocked or unreachable.           |
| `--mock-upstream`   | CI gating; isolate signet from upstream noise. |

## CI gating with `--gate`

`--gate p95=10ms,p99=20ms` exits 1 if the pipeline-total p95 exceeds
10 ms or the p99 exceeds 20 ms. Combine with `--mock-upstream` so
your CI doesn't need an upstream to run.

### GitHub Actions example

```yaml
jobs:
  bench:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install -e .[bench]
      - name: signet bench
        run: |
          signet bench \
            --mock-upstream \
            --config ./pipeline.py \
            --requests 1000 \
            --format json \
            --gate p95=10ms,p99=20ms \
            > bench.json
      - uses: actions/upload-artifact@v4
        with:
          name: bench
          path: bench.json
```

The JSON output (`--format json`) is a stable schema (`schema_version: 1`)
so a dashboard or trend graph can consume it without re-parsing the
markdown.

## What moves the numbers

* **Adding a check.** A new ADMISSION check costs whatever work it
  does -- usually micros to single-digit milliseconds. The bench
  surfaces this in the per-check row.
* **External calls.** A check that calls an LLM judge or a sandbox
  runner is the single biggest mover -- bound it with
  `timeout_seconds` so a stuck dependency can't tail-latency the
  whole gate.
* **Pipeline order.** Cheap ADMISSION checks first, expensive ones
  last. Rate limits run *after* content scans by default (priority
  100) so a refused request never costs a token. See
  `signet.core.check.Check.priority`.

## Sample size guidance

`--requests 100` is enough to get a stable p50; the p99 is one
sample out of about 100, so it bounces. Prefer `--requests 1000` for
tail percentiles, and `--requests 5000` if you need to compare runs
across PRs without false-positive regressions from sample noise.

The bench prints a "small sample size" note in the report when
`--requests < 200`.

## What `signet bench` does *not* do

* It does not measure throughput or requests-per-second. For that,
  drive HTTP load with `wrk`, `vegeta`, or `k6` against a running
  `signet serve`.
* It does not exercise COMMITMENT-stage checks unless the harness
  is extended to emit synthetic tool calls. A real tool-call
  workload should be measured separately.
* It does not warm caches. Every run is cold. If your pipeline has
  a caching check, run a warmup before the real measurement.
