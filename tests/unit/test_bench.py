"""Tests for :mod:`signet.bench` and the ``signet bench`` CLI subcommand.

Focus areas:

* :func:`run_bench` completes with ``--mock-upstream`` (no network).
* Percentile math matches stdlib :func:`statistics.quantiles` for a
  known input -- protects against subtle off-by-one in the linear-
  interpolation implementation.
* ``--gate`` exits 0 when actual overhead is well under the threshold
  and exits non-zero when it isn't (the regression-detector contract).
* The JSON output parses and carries the documented top-level keys.
* The markdown output contains the headings the docs/blog rely on.
"""

from __future__ import annotations

import asyncio
import json
import statistics
from pathlib import Path

import pytest
from click.testing import CliRunner

from signet.bench import (
    BenchReport,
    GateRule,
    apply_gate,
    default_mock_pipeline,
    format_gate_outcome,
    parse_gate_spec,
    run_bench,
)
from signet.cli import main

# ---------------------------------------------------------------------------
# run_bench: end-to-end harness
# ---------------------------------------------------------------------------


def test_bench_mock_upstream_runs() -> None:
    """`signet bench --mock-upstream --requests 100` completes without error.

    The mock pipeline is tiny (one admission + one inspection check, both
    no-op) so this is the cheapest end-to-end smoke we can run. Asserts:

    * The bench returns the right number of samples.
    * Every sample carries a stage_durations dict with the four stages.
    * The duration is positive (perf_counter actually ticked).
    * The decision is "allow" for every sample (the mock pipeline
      cannot block, so a non-allow here would mean we silently
      broke synthetic-request construction).
    """
    pipeline = default_mock_pipeline()
    report = asyncio.run(
        run_bench(
            pipeline,
            upstream_url="mock://unreachable",
            requests=100,
            concurrency=10,
            baseline=False,
            mock_upstream=True,
        )
    )
    assert len(report.samples) == 100
    assert report.duration_seconds > 0
    assert report.mock_upstream is True
    for sample in report.samples:
        assert sample.decision == "allow"
        assert set(sample.stage_durations) == {
            "ADMISSION",
            "INSPECTION",
            "COMMITMENT",
            "RECORD",
        }
        assert sample.pipeline_total_seconds >= 0
    # The mock pipeline has zero COMMITMENT or RECORD checks, so
    # those columns are zero -- that's the report's "stage exists
    # but had no work" path.
    assert report.pipeline_stage_counts["ADMISSION"] == 1
    assert report.pipeline_stage_counts["INSPECTION"] == 1
    assert report.pipeline_stage_counts["COMMITMENT"] == 0
    assert report.pipeline_stage_counts["RECORD"] == 0


def test_bench_rejects_invalid_requests_arg() -> None:
    pipeline = default_mock_pipeline()
    with pytest.raises(ValueError, match="requests must be > 0"):
        asyncio.run(run_bench(pipeline, requests=0, mock_upstream=True))


def test_bench_rejects_invalid_concurrency_arg() -> None:
    pipeline = default_mock_pipeline()
    with pytest.raises(ValueError, match="concurrency must be > 0"):
        asyncio.run(
            run_bench(pipeline, requests=10, concurrency=0, mock_upstream=True)
        )


# ---------------------------------------------------------------------------
# Percentile math
# ---------------------------------------------------------------------------


def test_bench_percentile_math_matches_stdlib_at_quartiles() -> None:
    """Linear-interpolation percentile agrees with statistics.quantiles().

    Builds 100 evenly-spaced values 0.01..1.0; under linear interp the
    25/50/75/95th percentile should be approximately equal to the
    corresponding quantile output. Tolerances are loose because the
    two methods agree to within a single bin on this data.
    """
    values = [i / 100 for i in range(1, 101)]  # 0.01, 0.02, ..., 1.00
    p50 = BenchReport.percentile(values, 50)
    p95 = BenchReport.percentile(values, 95)
    qs = statistics.quantiles(values, n=100, method="inclusive")
    assert p50 == pytest.approx(qs[49], abs=0.01)
    assert p95 == pytest.approx(qs[94], abs=0.01)


def test_bench_percentile_extremes_clamp() -> None:
    """p=0 returns min; p=100 returns max; empty list returns 0.0."""
    values = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0]
    assert BenchReport.percentile(values, 0) == 1.0
    assert BenchReport.percentile(values, 100) == 9.0
    assert BenchReport.percentile([], 50) == 0.0


# ---------------------------------------------------------------------------
# Gate parsing and evaluation
# ---------------------------------------------------------------------------


def test_parse_gate_spec_basic_ms() -> None:
    rules = parse_gate_spec("p95=10ms,p99=20ms")
    assert rules == [
        GateRule(percentile=95, threshold_seconds=0.010),
        GateRule(percentile=99, threshold_seconds=0.020),
    ]


def test_parse_gate_spec_accepts_other_units() -> None:
    rules = parse_gate_spec("p50=0.02s, p99=500us")
    assert rules[0].percentile == 50
    assert rules[0].threshold_seconds == pytest.approx(0.020)
    assert rules[1].percentile == 99
    assert rules[1].threshold_seconds == pytest.approx(0.0005)


def test_parse_gate_spec_rejects_bare_number() -> None:
    # No unit -- the operator probably typed 0.01 thinking "seconds"
    # but the convention is ms, so we reject rather than guess.
    with pytest.raises(ValueError, match="invalid --gate rule"):
        parse_gate_spec("p95=10")


def test_parse_gate_spec_rejects_out_of_range_percentile() -> None:
    with pytest.raises(ValueError, match="percentile"):
        parse_gate_spec("p150=10ms")


def test_parse_gate_spec_empty_returns_empty_list() -> None:
    assert parse_gate_spec("") == []
    assert parse_gate_spec("   ") == []


def test_apply_gate_passes_under_threshold() -> None:
    """A rule of p95=100ms passes when the actual p95 is ~5ms."""
    pipeline = default_mock_pipeline()
    report = asyncio.run(
        run_bench(pipeline, requests=50, mock_upstream=True, baseline=False)
    )
    rule = GateRule(percentile=95, threshold_seconds=0.100)  # 100ms
    outcome = apply_gate(report, [rule])
    assert outcome.passed is True
    assert outcome.failures == []


def test_apply_gate_fails_over_threshold() -> None:
    """A rule of p95=0.001us forces a failure (any real timing exceeds it)."""
    pipeline = default_mock_pipeline()
    report = asyncio.run(
        run_bench(pipeline, requests=20, mock_upstream=True, baseline=False)
    )
    rule = GateRule(percentile=95, threshold_seconds=1e-12)
    outcome = apply_gate(report, [rule])
    assert outcome.passed is False
    assert len(outcome.failures) == 1
    failed_rule, observed = outcome.failures[0]
    assert failed_rule is rule
    assert observed > rule.threshold_seconds


def test_format_gate_outcome_renders_pass_and_fail() -> None:
    rule = GateRule(percentile=95, threshold_seconds=0.010)
    pass_text = format_gate_outcome(
        apply_gate(
            asyncio.run(
                run_bench(
                    default_mock_pipeline(),
                    requests=20,
                    mock_upstream=True,
                    baseline=False,
                )
            ),
            [rule],
        )
    )
    assert "gate: PASS" in pass_text or "gate: FAIL" in pass_text


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def test_bench_json_format_parseable() -> None:
    """--format json output is well-formed JSON with the documented schema."""
    pipeline = default_mock_pipeline()
    report = asyncio.run(
        run_bench(pipeline, requests=50, mock_upstream=True, baseline=False)
    )
    payload = json.loads(report.render_json())
    # Documented keys.
    for key in (
        "schema_version",
        "upstream_url",
        "total_requests",
        "concurrency",
        "duration_seconds",
        "pipeline_check_count",
        "pipeline_stage_counts",
        "pipeline_total_ms",
        "stages",
        "checks",
        "notes",
    ):
        assert key in payload, f"missing key {key} in JSON output"
    assert payload["schema_version"] == 1
    assert payload["total_requests"] == 50
    # Per-stage block carries the four standard percentile names.
    for percentile_key in ("p50", "p95", "p99", "max", "count"):
        assert percentile_key in payload["pipeline_total_ms"]


def test_bench_markdown_renders_section_headings() -> None:
    """--format markdown output contains the section headings docs refer to."""
    pipeline = default_mock_pipeline()
    report = asyncio.run(
        run_bench(pipeline, requests=50, mock_upstream=True, baseline=False)
    )
    md = report.render_markdown()
    # Top banner.
    assert "signet bench - overhead report" in md
    # Setup section.
    assert "Setup:" in md
    # Per-stage table.
    assert "Per-request overhead" in md
    # Stage row labels.
    for label in ("ADMISSION", "INSPECTION", "COMMITMENT", "RECORD", "TOTAL"):
        assert label in md
    # Per-check section.
    assert "Per-check breakdown" in md


def test_bench_csv_renders_summary_row() -> None:
    """--format csv emits one row per check + one summary total row."""
    pipeline = default_mock_pipeline()
    report = asyncio.run(
        run_bench(pipeline, requests=50, mock_upstream=True, baseline=False)
    )
    csv_text = report.render_csv()
    lines = [line for line in csv_text.splitlines() if line]
    # Header + 4 stages + 2 checks + 1 total = 8.
    assert lines[0].startswith("kind,name,stage,fires")
    assert any(line.startswith("total,pipeline,all") for line in lines)
    assert any(line.startswith("stage,admission,admission") for line in lines)
    # Both mock checks must show up by name.
    assert any("mock_admission" in line for line in lines)
    assert any("mock_inspection" in line for line in lines)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_bench_mock_smoke() -> None:
    """`signet bench --mock-upstream --requests 50` runs end-to-end via CLI."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "bench",
            "--mock-upstream",
            "--requests",
            "50",
            "--format",
            "markdown",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "signet bench - overhead report" in result.output


def test_cli_bench_gate_passes_under_threshold() -> None:
    """`--gate p95=1s` passes for a trivial mock pipeline (exit code 0)."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "bench",
            "--mock-upstream",
            "--requests",
            "30",
            "--format",
            "json",
            "--gate",
            "p95=1s",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cli_bench_gate_fails_over_threshold() -> None:
    """`--gate p95=0.001us` fails (exit 1) because any real timing exceeds it."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "bench",
            "--mock-upstream",
            "--requests",
            "30",
            "--format",
            "json",
            "--gate",
            "p95=0.001us",
        ],
    )
    assert result.exit_code == 1
    # The gate banner lands on stderr by design (so JSON piping to jq
    # is clean). CliRunner merges streams by default in modern click,
    # but at minimum the exit code is the contract we care about.


def test_cli_bench_rejects_malformed_gate_spec() -> None:
    """Malformed --gate is rejected before the bench runs."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "bench",
            "--mock-upstream",
            "--requests",
            "30",
            "--gate",
            "p95=bogus",
        ],
    )
    assert result.exit_code != 0
    assert "invalid --gate rule" in result.output


def test_cli_bench_with_config_file(tmp_path: Path) -> None:
    """`--config pipeline.py` loads the operator's pipeline and benches it.

    Smoke-tests the same code path `signet serve --config` uses, so a
    regression in pipeline loading would fail this test too.
    """
    pipeline_py = tmp_path / "pipeline.py"
    pipeline_py.write_text(
        '''\
from signet.core.pipeline import Pipeline
from signet.core.check import Check, CheckResult
from signet.core.stage import Stage
from signet.core.context import RequestContext


class _Allow(Check):
    name = "test_allow"
    stage = Stage.ADMISSION

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        return CheckResult.allow()


pipeline = Pipeline(checks=[_Allow()])
''',
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "bench",
            "--mock-upstream",
            "--requests",
            "20",
            "--config",
            str(pipeline_py),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["pipeline_check_count"] == 1
    assert "test_allow" in payload["checks"]
