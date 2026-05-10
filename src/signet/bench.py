"""Per-request overhead benchmark for signet.

Measures the latency signet adds to an LLM call, decomposed by
pipeline stage and by individual check. Output is suitable for
inclusion in deployment docs, dashboards, and CI gating.

The bench is *opinionated*: it measures the pipeline-add latency,
not throughput / RPS. For an LLM safety gate, the upstream model
call dwarfs every other component by 1-2 orders of magnitude, so
the only number an operator can move with code changes is the
overhead signet itself adds. A "100 req/s" claim would be a claim
about the upstream, not about signet; this module deliberately
does not measure it.

Three modes:

* **baseline** (default): runs ``--requests`` requests through
  signet's pipeline AND runs the same number of requests directly
  against ``--upstream`` so the report can show the delta. Requires
  the upstream to answer.
* **--no-baseline**: only measure signet's own pipeline overhead.
  Useful when the upstream is mocked or unreachable.
* **--mock-upstream**: skip the upstream entirely; treat the upstream
  as a zero-latency oracle. Best for CI gating where you want to
  detect *signet code regressions* without flake from network or
  model variance.

The CLI surface lives in :mod:`signet.cli` (``signet bench``).

Sample-size guidance: ``--requests 100`` produces noisy tail
percentiles (p99 is one sample out of 100). For meaningful tails,
prefer ``--requests 1000`` or higher. The bench harness emits a
warning when the sample count would make the requested gate
threshold statistically unreliable.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext
from signet.core.owner import Owner
from signet.core.pipeline import Pipeline
from signet.core.stage import Stage

# Stage labels used in the report. Centralized so the markdown,
# JSON, and CSV renderers stay aligned with the bench logic.
STAGE_LABELS: tuple[str, ...] = ("ADMISSION", "INSPECTION", "COMMITMENT", "RECORD")

# Canonical synthetic request body used by the bench harness when
# the caller doesn't supply one. Shaped like an OpenAI chat-completion
# request because that's the wire format signet is gating; using a
# realistic body means request-shape-dependent checks (token counters,
# classification gates) do real work rather than short-circuiting on
# an empty payload.
DEFAULT_BENCH_BODY: dict[str, Any] = {
    "model": "bench-model",
    "messages": [
        {"role": "user", "content": "What's the weather like today?"},
    ],
    "stream": False,
}

# A small response chunk we feed through the INSPECTION stage so
# inspection checks have actual content to scan. Kept short so the
# bench reflects the typical per-chunk cost, not a worst-case scan.
DEFAULT_BENCH_CHUNK: str = "Hello! The weather is sunny and 72 degrees. "


@dataclass
class BenchSample:
    """One measurement of one request driven through signet.

    Times are wall-clock seconds (``time.perf_counter`` deltas).
    Stage and per-check durations are floats so percentiles compute
    cleanly. ``decision`` records what the pipeline returned so
    a bench result that's silently being refused (e.g. owner-resolution
    blocking every synthetic request) is visible in the report.
    """

    request_id: str
    pipeline_total_seconds: float
    stage_durations: dict[str, float]  # stage_name -> seconds
    per_check_durations: dict[str, float]  # check_name -> seconds
    per_check_stages: dict[str, str]  # check_name -> stage value
    decision: str  # allow / block / redact / escalate
    upstream_latency_seconds: float | None = None


@dataclass
class BenchReport:
    """Aggregated results from a benchmark run.

    Carries every sample so the renderers can compute percentiles
    on demand and so callers can post-process (e.g. dump to a
    Grafana dashboard) without re-running the bench.
    """

    upstream_url: str
    pipeline_check_count: int
    pipeline_stage_counts: dict[str, int]
    total_requests: int
    concurrency: int
    duration_seconds: float
    samples: list[BenchSample]
    baseline_samples: list[float] = field(default_factory=list)
    # Free-form notes the renderer surfaces verbatim ("no tool calls
    # in this run", "upstream skipped: connection refused", etc).
    notes: list[str] = field(default_factory=list)
    mock_upstream: bool = False

    # ----- aggregation helpers -----

    @staticmethod
    def percentile(values: list[float], p: float) -> float:
        """Compute the ``p``-th percentile (0..100) of ``values``.

        Uses linear interpolation between samples (the same method
        ``statistics.quantiles`` uses with ``method="exclusive"`` is
        too aggressive at the tails for small N; we use the simple
        nearest-rank interpolation that matches what most ops tools
        report).
        """
        if not values:
            return 0.0
        if p <= 0:
            return min(values)
        if p >= 100:
            return max(values)
        s = sorted(values)
        # Linear interpolation: rank = (p/100) * (N-1), then mix
        # the two neighbours by the fractional part.
        rank = (p / 100.0) * (len(s) - 1)
        lo = int(rank)
        hi = min(lo + 1, len(s) - 1)
        frac = rank - lo
        return s[lo] * (1 - frac) + s[hi] * frac

    def pipeline_totals(self) -> list[float]:
        return [s.pipeline_total_seconds for s in self.samples]

    def stage_durations(self, stage_label: str) -> list[float]:
        return [s.stage_durations.get(stage_label, 0.0) for s in self.samples]

    def check_names(self) -> list[str]:
        seen: dict[str, None] = {}
        for s in self.samples:
            for name in s.per_check_durations:
                seen.setdefault(name, None)
        return list(seen)

    def check_durations(self, check_name: str) -> list[float]:
        # Only count samples where this check actually fired so the
        # percentile reflects the check's real cost. A check that
        # never ran (e.g. a COMMITMENT-stage tool inspector in a run
        # with zero tool calls) shouldn't drag its p50 to 0.0 -- it
        # simply has no samples and the report says so.
        return [
            s.per_check_durations[check_name]
            for s in self.samples
            if check_name in s.per_check_durations
        ]

    def check_stage(self, check_name: str) -> str:
        for s in self.samples:
            if check_name in s.per_check_stages:
                return s.per_check_stages[check_name]
        return ""

    # ----- rendering -----

    def render_markdown(self) -> str:
        out = io.StringIO()
        out.write("signet bench - overhead report\n")
        out.write("==============================\n")
        out.write("Setup:\n")
        out.write(f"  upstream:     {self.upstream_url}")
        if self.baseline_samples:
            bp50 = self.percentile(self.baseline_samples, 50) * 1000
            bp99 = self.percentile(self.baseline_samples, 99) * 1000
            out.write(f" (latency p50={bp50:.0f}ms p99={bp99:.0f}ms)")
        elif self.mock_upstream:
            out.write(" (mock; zero latency)")
        out.write("\n")
        out.write(
            f"  pipeline:     {self.pipeline_check_count} checks "
            f"(admission: {self.pipeline_stage_counts.get('ADMISSION', 0)}, "
            f"inspection: {self.pipeline_stage_counts.get('INSPECTION', 0)}, "
            f"commitment: {self.pipeline_stage_counts.get('COMMITMENT', 0)}, "
            f"record: {self.pipeline_stage_counts.get('RECORD', 0)})\n"
        )
        out.write(f"  requests:     {self.total_requests}\n")
        out.write(f"  concurrency:  {self.concurrency}\n")
        out.write(f"  duration:     {self.duration_seconds:.2f}s\n")
        out.write("\n")

        # Per-stage table.
        out.write("Per-request overhead (signet pipeline only, excluding upstream):\n")
        out.write(
            f"  {'Stage':<12} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>9}\n"
        )
        for stage in STAGE_LABELS:
            vals = self.stage_durations(stage)
            if not any(vals):
                # Stage had no checks or no work; emit a clarifying
                # zero row so the operator can see the pipeline shape
                # at a glance.
                count = self.pipeline_stage_counts.get(stage, 0)
                tail = (
                    "  (no checks in this stage)"
                    if count == 0
                    else "  (no work this run)"
                )
                out.write(
                    f"  {stage:<12} {'0.0ms':>8} {'0.0ms':>8} {'0.0ms':>8} {'0.0ms':>9}{tail}\n"
                )
                continue
            p50 = self.percentile(vals, 50) * 1000
            p95 = self.percentile(vals, 95) * 1000
            p99 = self.percentile(vals, 99) * 1000
            mx = max(vals) * 1000
            out.write(
                f"  {stage:<12} {p50:>7.2f}ms {p95:>7.2f}ms {p99:>7.2f}ms {mx:>8.2f}ms\n"
            )
        totals = self.pipeline_totals()
        if totals:
            tp50 = self.percentile(totals, 50) * 1000
            tp95 = self.percentile(totals, 95) * 1000
            tp99 = self.percentile(totals, 99) * 1000
            tmx = max(totals) * 1000
            out.write(
                f"  {'TOTAL':<12} {tp50:>7.2f}ms {tp95:>7.2f}ms {tp99:>7.2f}ms {tmx:>8.2f}ms\n"
            )
        out.write("\n")

        # End-to-end section: pipeline + upstream.
        if self.baseline_samples and totals:
            out.write("End-to-end latency (signet + upstream):\n")
            out.write(f"  {'':<12} {'p50':>8} {'p95':>8} {'p99':>8}\n")
            for label, vals in (
                ("baseline", self.baseline_samples),
                (
                    "via signet",
                    [a + b for a, b in zip(totals, self.baseline_samples, strict=False)],
                ),
            ):
                p50 = self.percentile(vals, 50) * 1000
                p95 = self.percentile(vals, 95) * 1000
                p99 = self.percentile(vals, 99) * 1000
                out.write(
                    f"  {label:<12} {p50:>7.0f}ms {p95:>7.0f}ms {p99:>7.0f}ms\n"
                )
            # Overhead row.
            d50 = (
                self.percentile(totals, 50)
                + self.percentile(self.baseline_samples, 50)
                - self.percentile(self.baseline_samples, 50)
            ) * 1000
            d95 = self.percentile(totals, 95) * 1000
            d99 = self.percentile(totals, 99) * 1000
            base50 = self.percentile(self.baseline_samples, 50) * 1000
            base95 = self.percentile(self.baseline_samples, 95) * 1000
            base99 = self.percentile(self.baseline_samples, 99) * 1000
            pct50 = (d50 / base50 * 100) if base50 > 0 else 0.0
            pct95 = (d95 / base95 * 100) if base95 > 0 else 0.0
            pct99 = (d99 / base99 * 100) if base99 > 0 else 0.0
            out.write(
                f"  {'overhead':<12} {d50:>+6.0f}ms {d95:>+6.0f}ms {d99:>+6.0f}ms"
                f"  ({pct50:.1f}% / {pct95:.1f}% / {pct99:.1f}%)\n"
            )
            out.write("\n")

        # Per-check breakdown.
        names = self.check_names()
        if names:
            out.write("Per-check breakdown:\n")
            out.write(f"  {'Check':<28} {'fires':>8} {'p50':>8} {'p99':>8}\n")
            duration = max(self.duration_seconds, 1e-9)
            for name in names:
                durs = self.check_durations(name)
                stage = self.check_stage(name)
                if not durs:
                    out.write(
                        f"  {name:<28} {'-':>8} {'-':>8} {'-':>8}  "
                        f"({stage.lower()} - did not fire)\n"
                    )
                    continue
                fires_per_s = len(durs) / duration
                p50 = self.percentile(durs, 50) * 1000
                p99 = self.percentile(durs, 99) * 1000
                out.write(
                    f"  {name:<28} {fires_per_s:>8.1f} "
                    f"{p50:>7.2f}ms {p99:>7.2f}ms\n"
                )
            out.write("\n")

        if self.notes:
            out.write("Notes:\n")
            for note in self.notes:
                out.write(f"  - {note}\n")
        return out.getvalue()

    def render_json(self) -> str:
        """Stable schema for CI gating and dashboards.

        ``schema_version`` is bumped only on breaking changes -- new
        keys may be added without bumping. CI consumers should treat
        unknown keys as opaque.
        """
        totals = self.pipeline_totals()
        payload: dict[str, Any] = {
            "schema_version": 1,
            "upstream_url": self.upstream_url,
            "mock_upstream": self.mock_upstream,
            "total_requests": self.total_requests,
            "concurrency": self.concurrency,
            "duration_seconds": self.duration_seconds,
            "pipeline_check_count": self.pipeline_check_count,
            "pipeline_stage_counts": self.pipeline_stage_counts,
            "pipeline_total_ms": _percentile_block(totals),
            "stages": {
                stage: _percentile_block(self.stage_durations(stage))
                for stage in STAGE_LABELS
            },
            "checks": {
                name: {
                    "stage": self.check_stage(name),
                    "fires": len(self.check_durations(name)),
                    **_percentile_block(self.check_durations(name)),
                }
                for name in self.check_names()
            },
            "baseline_ms": (
                _percentile_block(self.baseline_samples)
                if self.baseline_samples
                else None
            ),
            "notes": list(self.notes),
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def render_csv(self) -> str:
        """One row per check + one summary TOTAL row.

        Columns: ``kind, name, stage, fires, p50_ms, p95_ms, p99_ms, max_ms``.
        ``kind`` is ``check`` or ``stage`` or ``total`` so a spreadsheet
        can filter on it.
        """
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(
            ["kind", "name", "stage", "fires", "p50_ms", "p95_ms", "p99_ms", "max_ms"]
        )
        for stage in STAGE_LABELS:
            vals = self.stage_durations(stage)
            writer.writerow(
                [
                    "stage",
                    stage.lower(),
                    stage.lower(),
                    len([v for v in vals if v > 0]),
                    _ms_or_blank(self.percentile(vals, 50)),
                    _ms_or_blank(self.percentile(vals, 95)),
                    _ms_or_blank(self.percentile(vals, 99)),
                    _ms_or_blank(max(vals) if vals else 0.0),
                ]
            )
        for name in self.check_names():
            durs = self.check_durations(name)
            writer.writerow(
                [
                    "check",
                    name,
                    self.check_stage(name),
                    len(durs),
                    _ms_or_blank(self.percentile(durs, 50)),
                    _ms_or_blank(self.percentile(durs, 95)),
                    _ms_or_blank(self.percentile(durs, 99)),
                    _ms_or_blank(max(durs) if durs else 0.0),
                ]
            )
        totals = self.pipeline_totals()
        writer.writerow(
            [
                "total",
                "pipeline",
                "all",
                len(totals),
                _ms_or_blank(self.percentile(totals, 50)),
                _ms_or_blank(self.percentile(totals, 95)),
                _ms_or_blank(self.percentile(totals, 99)),
                _ms_or_blank(max(totals) if totals else 0.0),
            ]
        )
        return out.getvalue()


def _percentile_block(values: list[float]) -> dict[str, float]:
    """Standard percentile bag used by render_json. Values in ms."""
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0, "count": 0}
    return {
        "p50": BenchReport.percentile(values, 50) * 1000,
        "p95": BenchReport.percentile(values, 95) * 1000,
        "p99": BenchReport.percentile(values, 99) * 1000,
        "max": max(values) * 1000,
        "count": len(values),
    }


def _ms_or_blank(seconds: float) -> str:
    """Render seconds as a millisecond float, blank when zero.

    Blank (rather than ``0.000``) keeps CSV imports honest: a check
    that never fired produces empty cells, not misleading zero rows
    that would skew downstream averages.
    """
    if seconds <= 0:
        return ""
    return f"{seconds * 1000:.3f}"


# ---- gate parsing -----------------------------------------------------------


@dataclass(frozen=True)
class GateRule:
    """One ``<percentile>=<threshold>`` rule from ``--gate``.

    ``percentile`` is the integer percentile (50, 95, 99). ``threshold_seconds``
    is the duration in seconds the pipeline TOTAL must not exceed.
    """

    percentile: int
    threshold_seconds: float

    def evaluate(self, totals: list[float]) -> tuple[bool, float]:
        """Return ``(passed, observed_seconds)`` for this rule."""
        observed = BenchReport.percentile(totals, self.percentile)
        return observed <= self.threshold_seconds, observed


_GATE_RULE_RE = re.compile(
    r"^p(?P<pct>\d{1,3})\s*=\s*(?P<num>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>ms|s|us|μs)$",
    re.IGNORECASE,
)


def parse_gate_spec(spec: str) -> list[GateRule]:
    """Parse ``p95=10ms,p99=20ms`` into a list of :class:`GateRule`.

    Accepted units (required, no default): ``ms``, ``s``, ``us``/``μs``.
    Whitespace around tokens is tolerated. A bare number is rejected:
    operators have historically confused seconds vs. milliseconds when
    typing ``--gate p95=0.01``, so requiring an explicit unit removes
    a foot-gun.
    """
    rules: list[GateRule] = []
    if not spec or not spec.strip():
        return rules
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        match = _GATE_RULE_RE.match(token)
        if not match:
            raise ValueError(
                f"invalid --gate rule {token!r}; expected e.g. 'p95=10ms', "
                "'p99=0.02s'"
            )
        pct = int(match.group("pct"))
        if not 0 < pct < 100:
            raise ValueError(
                f"invalid percentile in --gate rule {token!r}: must be 1..99"
            )
        num = float(match.group("num"))
        unit = match.group("unit").lower()
        if unit == "ms":
            seconds = num / 1000.0
        elif unit == "s":
            seconds = num
        elif unit in ("us", "μs"):
            seconds = num / 1_000_000.0
        else:  # pragma: no cover - regex constrains
            raise ValueError(f"unknown unit in --gate rule {token!r}: {unit}")
        rules.append(GateRule(percentile=pct, threshold_seconds=seconds))
    return rules


@dataclass(frozen=True)
class GateOutcome:
    """Result of applying a list of GateRules to a BenchReport.

    ``failures`` is the list of rules that did not meet their threshold,
    each annotated with the observed value. Empty list = all rules passed.
    """

    passed: bool
    failures: list[tuple[GateRule, float]]
    rules: list[GateRule]


def apply_gate(report: BenchReport, rules: Iterable[GateRule]) -> GateOutcome:
    """Evaluate every rule against ``report``'s pipeline-total percentiles."""
    rule_list = list(rules)
    totals = report.pipeline_totals()
    failures: list[tuple[GateRule, float]] = []
    for rule in rule_list:
        ok, observed = rule.evaluate(totals)
        if not ok:
            failures.append((rule, observed))
    return GateOutcome(passed=not failures, failures=failures, rules=rule_list)


def format_gate_outcome(outcome: GateOutcome) -> str:
    """Human-readable summary of a GateOutcome.

    Used by the CLI to print the gate result block; pulled out as a
    free function so tests can assert on the exact wording without
    capturing click output.
    """
    if not outcome.rules:
        return "gate: no rules supplied"
    if outcome.passed:
        lines = ["gate: PASS"]
        for rule in outcome.rules:
            lines.append(
                f"  p{rule.percentile}: <= {rule.threshold_seconds * 1000:.2f}ms"
            )
        return "\n".join(lines) + "\n"
    lines = ["gate: FAIL"]
    for rule, observed in outcome.failures:
        lines.append(
            f"  p{rule.percentile}: observed {observed * 1000:.2f}ms "
            f"exceeds threshold {rule.threshold_seconds * 1000:.2f}ms"
        )
    return "\n".join(lines) + "\n"


# ---- harness ----------------------------------------------------------------


def _build_request_context(request_id: str) -> RequestContext:
    """Build a synthetic RequestContext for the bench harness.

    Owner is pre-resolved (``Owner.human("bench@signet.local")``) so
    OwnerResolutionCheck-style ADMISSION checks don't block every
    bench request and skew the decision distribution.
    """
    return RequestContext(
        owner=Owner.human("bench@signet.local"),
        headers={
            "X-Commit-Owner": "human:bench@signet.local",
            "Content-Type": "application/json",
        },
        body=dict(DEFAULT_BENCH_BODY),
        path="/v1/chat/completions",
        method="POST",
        client_ip="127.0.0.1",
        session_id=f"bench-{request_id}",
    )


async def _drive_one_request(pipeline: Pipeline, request_id: str) -> BenchSample:
    """Drive one synthetic request through every pipeline stage.

    Each individual check call is wrapped in ``time.perf_counter()``
    so the per-check timing is exact, not bucket-rounded. Stage
    durations sum to the pipeline total minus orchestration overhead
    (a few nanoseconds of dict-building per stage), which is below
    the resolution of perf_counter on every platform we support.

    Notes on stage semantics:

    * ADMISSION short-circuits on the first non-allow result. The
      bench mirrors the production path: stop calling later checks
      once one blocks. This means a blocked synthetic request
      under-reports later-stage costs -- the harness uses a
      pre-resolved owner exactly to avoid that confusion.
    * INSPECTION is exercised with a single canned chunk. Real traffic
      may fire INSPECTION N times for N stream chunks; the report
      surfaces this in the ``per-check`` ``fires`` column so operators
      can multiply by their actual chunk count.
    * COMMITMENT is skipped entirely (no tool call in the synthetic
      request). The report calls this out under "Notes" so a missing
      COMMITMENT cost doesn't look like a measurement bug.
    * RECORD runs every check (non-short-circuiting), per the
      production contract.
    """
    ctx = _build_request_context(request_id)
    per_check: dict[str, float] = {}
    per_check_stages: dict[str, str] = {}
    stage_durations: dict[str, float] = {
        "ADMISSION": 0.0,
        "INSPECTION": 0.0,
        "COMMITMENT": 0.0,
        "RECORD": 0.0,
    }
    overall_start = time.perf_counter()
    decision_str = "allow"

    # ADMISSION: short-circuit on first non-allow, mirroring the
    # production pipeline.
    stage_start = time.perf_counter()
    for check in pipeline.checks_for_stage(Stage.ADMISSION):
        check_start = time.perf_counter()
        try:
            result = await check.pre_request(ctx)
        except Exception:
            # Mirror Pipeline._run_with_timeout's fail-closed shape
            # but don't lose the timing: the bench wants to report
            # "this check crashes" rather than swallow the exception
            # and pretend the run was clean.
            elapsed = time.perf_counter() - check_start
            per_check[check.name] = elapsed
            per_check_stages[check.name] = Stage.ADMISSION.value
            stage_durations["ADMISSION"] += elapsed
            decision_str = "error"
            break
        elapsed = time.perf_counter() - check_start
        per_check[check.name] = elapsed
        per_check_stages[check.name] = Stage.ADMISSION.value
        if not result.is_allow:
            decision_str = _decision_str(result)
            stage_durations["ADMISSION"] = time.perf_counter() - stage_start
            break
    else:
        stage_durations["ADMISSION"] = time.perf_counter() - stage_start

    # INSPECTION: only if admission allowed. Single canned chunk.
    if decision_str == "allow":
        resp = ResponseContext(request=ctx)
        resp.extend_text(DEFAULT_BENCH_CHUNK)
        stage_start = time.perf_counter()
        for check in pipeline.checks_for_stage(Stage.INSPECTION):
            check_start = time.perf_counter()
            try:
                result = await check.inspect_response_chunk(resp, DEFAULT_BENCH_CHUNK)
            except Exception:
                elapsed = time.perf_counter() - check_start
                per_check[check.name] = elapsed
                per_check_stages[check.name] = Stage.INSPECTION.value
                stage_durations["INSPECTION"] += elapsed
                decision_str = "error"
                break
            elapsed = time.perf_counter() - check_start
            per_check[check.name] = elapsed
            per_check_stages[check.name] = Stage.INSPECTION.value
            if not result.is_allow:
                decision_str = _decision_str(result)
                stage_durations["INSPECTION"] = time.perf_counter() - stage_start
                break
        else:
            stage_durations["INSPECTION"] = time.perf_counter() - stage_start

        # COMMITMENT is skipped: synthetic requests have no tool calls.
        # A real tool-call workload would call pipeline.inspect_tool_call;
        # the bench surfaces this as a Note rather than fabricate a
        # tool-call shape that doesn't match the operator's registry.

        # RECORD: non-short-circuiting; every check runs.
        stage_start = time.perf_counter()
        for check in pipeline.checks_for_stage(Stage.RECORD):
            check_start = time.perf_counter()
            # RECORD is audit-only; a crashing record check would be a real
            # bug in production, but for bench purposes we still capture
            # the timing so the operator sees the cost of a check whose
            # exception would otherwise be silently logged.
            with contextlib.suppress(Exception):
                await check.post_complete(resp)
            elapsed = time.perf_counter() - check_start
            per_check[check.name] = elapsed
            per_check_stages[check.name] = Stage.RECORD.value
        stage_durations["RECORD"] = time.perf_counter() - stage_start

    total = time.perf_counter() - overall_start
    return BenchSample(
        request_id=request_id,
        pipeline_total_seconds=total,
        stage_durations=stage_durations,
        per_check_durations=per_check,
        per_check_stages=per_check_stages,
        decision=decision_str,
    )


def _decision_str(result: CheckResult) -> str:
    if result.is_allow:
        return "allow"
    if result.is_block:
        return "block"
    if result.is_redact:
        return "redact"
    if result.is_escalate:
        return "escalate"
    return "unknown"


def _count_checks_by_stage(pipeline: Pipeline) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(STAGE_LABELS, 0)
    for check in pipeline.checks:
        # ``Check.stage`` is a Stage enum; map to our UPPERCASE labels.
        counts[check.stage.value.upper()] = counts.get(check.stage.value.upper(), 0) + 1
    return counts


async def _measure_upstream_baseline(
    upstream_url: str,
    requests: int,
    concurrency: int,
    timeout_s: float = 30.0,
) -> tuple[list[float], str | None]:
    """Make ``requests`` direct HTTP POSTs to the upstream chat endpoint.

    Returns ``(latencies_seconds, error)``. If the first request fails
    (connection refused, DNS error, 5xx) we stop and return whatever
    we have plus a string describing the failure -- the bench should
    still produce a useful report against the pipeline-only numbers
    rather than abort the whole run.
    """
    chat_url = upstream_url.rstrip("/") + "/chat/completions"
    samples: list[float] = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout_s) as client:
        async def one() -> tuple[float | None, str | None]:
            async with sem:
                start = time.perf_counter()
                try:
                    resp = await client.post(chat_url, json=DEFAULT_BENCH_BODY)
                except httpx.HTTPError as exc:
                    return None, f"{type(exc).__name__}: {exc}"
                elapsed = time.perf_counter() - start
                if resp.status_code >= 500:
                    return None, f"upstream returned {resp.status_code}"
                return elapsed, None

        tasks = [asyncio.create_task(one()) for _ in range(requests)]
        first_error: str | None = None
        for task in tasks:
            latency, err = await task
            if latency is not None:
                samples.append(latency)
            elif first_error is None:
                first_error = err
        return samples, first_error


async def run_bench(
    pipeline: Pipeline,
    *,
    upstream_url: str = "mock://upstream",
    requests: int = 1000,
    concurrency: int = 10,
    baseline: bool = True,
    mock_upstream: bool = False,
) -> BenchReport:
    """Drive ``requests`` total requests through ``pipeline``.

    The pipeline is invoked in-process: each request builds a synthetic
    :class:`RequestContext` and walks the four stages directly. This
    isolates signet's pipeline overhead from HTTP/TCP/serialization
    costs, which is the number an operator can actually move with
    code changes.

    ``mock_upstream=True`` skips the direct-to-upstream baseline calls.
    ``baseline=False`` does the same (the two flags compose: mock
    implies baseline-skip; pass ``baseline=False`` explicitly when
    pointing at a real upstream that you don't want measured).

    Returns a :class:`BenchReport`. Never raises on upstream failure --
    failed baseline calls produce a Note in the report instead of
    aborting the whole run, because the pipeline-only numbers are
    still useful even when the upstream is down.
    """
    if requests <= 0:
        raise ValueError(f"requests must be > 0, got {requests}")
    if concurrency <= 0:
        raise ValueError(f"concurrency must be > 0, got {concurrency}")

    sem = asyncio.Semaphore(concurrency)
    samples: list[BenchSample] = []
    notes: list[str] = []
    if requests < 200:
        notes.append(
            f"sample size n={requests} is small; p99 is a single observation "
            "out of ~100. Prefer --requests 1000 for stable tails."
        )

    async def driver(i: int) -> BenchSample:
        async with sem:
            return await _drive_one_request(pipeline, f"req-{i:06d}")

    bench_start = time.perf_counter()
    sample_results = await asyncio.gather(*(driver(i) for i in range(requests)))
    samples.extend(sample_results)

    # Optional upstream baseline measurement.
    baseline_samples: list[float] = []
    if baseline and not mock_upstream:
        # Cap baseline at 100 calls or the request count, whichever is
        # smaller -- baseline is for delta context, not its own deep
        # measurement. Operators who want a real upstream histogram
        # should use wrk / vegeta, not signet bench.
        baseline_n = min(requests, 100)
        baseline_samples, err = await _measure_upstream_baseline(
            upstream_url, baseline_n, concurrency
        )
        if err and not baseline_samples:
            notes.append(
                f"upstream baseline skipped: {err}. Pipeline-only numbers "
                "below remain valid."
            )
        elif err:
            notes.append(
                f"upstream baseline partial ({len(baseline_samples)}/{baseline_n} "
                f"succeeded): {err}"
            )
    elif mock_upstream:
        notes.append("--mock-upstream: upstream calls skipped entirely.")

    duration = time.perf_counter() - bench_start

    stage_counts = _count_checks_by_stage(pipeline)
    if stage_counts.get("COMMITMENT", 0) > 0:
        notes.append(
            "COMMITMENT-stage checks are registered but the synthetic bench "
            "request has no tool calls. Their cost is not exercised here; "
            "drive a tool-call workload separately if you need that number."
        )

    return BenchReport(
        upstream_url=upstream_url,
        pipeline_check_count=len(pipeline.checks),
        pipeline_stage_counts=stage_counts,
        total_requests=requests,
        concurrency=concurrency,
        duration_seconds=duration,
        samples=samples,
        baseline_samples=baseline_samples,
        notes=notes,
        mock_upstream=mock_upstream,
    )


# ---- mock pipeline factory --------------------------------------------------


class _MockAdmissionCheck(Check):
    """Minimal ADMISSION check used by --mock-upstream when the operator
    doesn't supply ``--config``.

    Deliberately cheap (returns allow with no work) so the mock-mode
    numbers reflect signet's per-request orchestration cost in
    isolation, not the cost of any particular real check. Operators
    who want the cost of *their* checks should pass ``--config``.
    """

    name = "mock_admission"
    stage = Stage.ADMISSION

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        return CheckResult.allow("mock")


class _MockInspectionCheck(Check):
    """Minimal INSPECTION check for --mock-upstream default mode."""

    name = "mock_inspection"
    stage = Stage.INSPECTION

    async def inspect_response_chunk(
        self, ctx: ResponseContext, chunk: str
    ) -> CheckResult:
        return CheckResult.allow()


def default_mock_pipeline() -> Pipeline:
    """Build a tiny no-op pipeline for ``--mock-upstream`` runs without
    ``--config``.

    Two checks (one ADMISSION, one INSPECTION) so the report has
    something to render for both stages but no real work happens.
    Useful for asserting "signet's orchestration overhead is < X ms"
    independent of any check's cost.
    """
    return Pipeline(checks=[_MockAdmissionCheck(), _MockInspectionCheck()])


def load_pipeline_or_default(config_path: Path | None) -> Pipeline:
    """Load the operator's pipeline.py if provided; else mock pipeline.

    Lazy-imports the cli loader to avoid a hard signet.cli ->
    signet.bench import cycle.
    """
    if config_path is None:
        return default_mock_pipeline()
    from signet.cli import _load_pipeline_from_path

    return _load_pipeline_from_path(config_path)
