"""Metrics — in-process Prometheus-format counters for /metrics.

Minimal-by-design: every signet decision is tracked as a labeled
counter in memory and exposed at ``/metrics`` in the Prometheus
text-exposition format. No external dependencies required.

This is sufficient for:

* Operations dashboards (Grafana, etc.) scraping the proxy
* Alerting on rates of blocks / escalations / errors
* Capacity planning (request rate, latency distribution roll-ups)

For deployments needing the full Prometheus feature surface
(histograms with bucket configuration, summaries, advanced labels),
plug in the official ``prometheus-client`` library against
:class:`Metrics` — it implements the same interface but with richer
backends.

Counters surfaced:

* ``signet_requests_total{path}`` — every request that reached
  :class:`signet.server.app.SignetApp`. The label set is intentionally
  small: the counter increments at handler entry before the pipeline
  has classified the request, so ``decision`` and ``status`` aren't
  yet known. Use :data:`signet_pipeline_decisions_total` for
  decision-shaped roll-ups.
* ``signet_pipeline_decisions_total{check, stage, decision}`` — every
  result returned by a check in the pipeline. ``stage`` is the
  ADMISSION/INSPECTION/COMMITMENT/RECORD lifecycle stage from the
  result metadata; an empty ``stage`` label denotes stageless
  synthetic rows (the per-request ``pipeline.complete`` row, etc.).
* ``signet_audit_chain_appends_total`` — total entries written to the
  audit chain
* ``signet_audit_anchor_failures_total{backend}`` — anchor backend
  failures (when external anchoring is configured)
* ``signet_check_duration_seconds{check, stage, decision}`` —
  histogram of per-check hook latency in seconds (v0.1.6)
* ``signet_shadow_would_have_blocked_total{check, stage, decision}`` —
  counter of non-allow decisions neutralized by shadow mode (v0.1.6).
  Mirrors the ``signet_pipeline_decisions_total`` label set so dashboards
  can join the two on (check, stage, decision).
* ``signet_response_text_truncated_total{cap_bytes}`` — counter of
  responses whose ``ResponseContext.accumulated_text`` saturated the
  per-response cap (v0.1.6 N2). Fires once per affected response.
  ``cap_bytes`` is the configured cap so dashboards can attribute spikes
  to a specific cap-policy setting.
* ``signet_uptime_seconds`` — gauge: seconds since the process started

Counters reset on process restart. For persistent metrics across
restarts, scrape into a long-term store (Prometheus, VictoriaMetrics,
etc.) — that's the standard pattern.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

#: Default histogram buckets (seconds). Tuned for sub-second checks —
#: most signet checks run in single-digit-millisecond budgets, with
#: outliers (LLM judges, sandboxed tools) potentially bleeding into
#: the seconds range. Buckets follow the Prometheus convention: each
#: bucket counts observations whose value is ``<=`` the upper bound;
#: a ``+Inf`` bucket is appended at render time so every observation
#: lands somewhere.
_DEFAULT_DURATION_BUCKETS: tuple[float, ...] = (
    0.001,
    0.005,
    0.01,
    0.05,
    0.1,
    0.5,
    1.0,
    5.0,
)

#: Process start time. Used by the uptime gauge.
_PROCESS_STARTED_AT = time.time()


@dataclass
class _Counter:
    """A single labeled counter."""

    name: str
    help_text: str
    # {label_tuple: value} where label_tuple is sorted (name, value) pairs
    values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)

    def inc(self, labels: dict[str, str], by: float = 1.0) -> None:
        key = tuple(sorted(labels.items()))
        self.values[key] = self.values.get(key, 0.0) + by

    def render(self) -> list[str]:
        out = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        for label_tuple, val in sorted(self.values.items()):
            if label_tuple:
                labels_str = "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in label_tuple) + "}"
            else:
                labels_str = ""
            out.append(f"{self.name}{labels_str} {val}")
        return out


@dataclass
class _Histogram:
    """A single labeled histogram with cumulative buckets.

    Each label combination owns its own per-bucket counter array, sum,
    and total count — the standard Prometheus histogram shape. Buckets
    are cumulative (each bucket counts observations ``<=`` its upper
    bound); a synthetic ``+Inf`` bucket equal to the total count is
    appended at render time so the histogram is always well-formed.
    """

    name: str
    help_text: str
    buckets: tuple[float, ...]
    # {label_tuple: ([count_per_bucket...], sum, total_count)}
    values: dict[tuple[tuple[str, str], ...], list[float]] = field(default_factory=dict)

    def observe(self, labels: dict[str, str], value: float) -> None:
        key = tuple(sorted(labels.items()))
        # Per-bucket counts + running sum + total count appended at the end
        # of the bucket array. Layout: [b0, b1, ..., bN-1, sum, count].
        slot = self.values.get(key)
        if slot is None:
            slot = [0.0] * (len(self.buckets) + 2)
            self.values[key] = slot
        for i, upper in enumerate(self.buckets):
            if value <= upper:
                slot[i] += 1.0
        slot[-2] += value  # sum
        slot[-1] += 1.0  # count

    def render(self) -> list[str]:
        out = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        for label_tuple, slot in sorted(self.values.items()):
            base_labels = list(label_tuple)
            for i, upper in enumerate(self.buckets):
                bucket_labels = [*base_labels, ("le", _format_bucket(upper))]
                labels_str = (
                    "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in bucket_labels) + "}"
                )
                out.append(f"{self.name}_bucket{labels_str} {slot[i]}")
            inf_labels = [*base_labels, ("le", "+Inf")]
            inf_labels_str = "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in inf_labels) + "}"
            total_count = slot[-1]
            out.append(f"{self.name}_bucket{inf_labels_str} {total_count}")
            base_labels_str = (
                "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in base_labels) + "}"
                if base_labels
                else ""
            )
            out.append(f"{self.name}_sum{base_labels_str} {slot[-2]}")
            out.append(f"{self.name}_count{base_labels_str} {total_count}")
        return out


def _format_bucket(upper: float) -> str:
    """Render a bucket upper bound. Integers and small decimals stay
    compact; this only affects the Prometheus exposition string."""
    if upper == int(upper):
        return f"{int(upper)}"
    return f"{upper:g}"


class Metrics:
    """Thread-safe in-process counter registry.

    Construct one instance per :class:`SignetApp` (the app does this
    automatically). Call :meth:`inc` to bump a counter; the
    ``/metrics`` endpoint renders the registry on demand via
    :meth:`render_prometheus`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, _Counter] = {
            "signet_requests_total": _Counter(
                "signet_requests_total",
                "Total HTTP requests received by signet's gated endpoints.",
            ),
            "signet_pipeline_decisions_total": _Counter(
                "signet_pipeline_decisions_total",
                "Pipeline check results, labeled by stage / check / decision.",
            ),
            "signet_audit_chain_appends_total": _Counter(
                "signet_audit_chain_appends_total",
                "Total entries written to the HMAC-chained audit log.",
            ),
            "signet_audit_anchor_failures_total": _Counter(
                "signet_audit_anchor_failures_total",
                "External anchor backend failures (recorded but not raised).",
            ),
            "signet_shadow_would_have_blocked_total": _Counter(
                "signet_shadow_would_have_blocked_total",
                (
                    "Non-allow decisions neutralized by shadow mode "
                    "(audit chain still records the original)."
                ),
            ),
            "signet_response_text_truncated_total": _Counter(
                "signet_response_text_truncated_total",
                (
                    "Responses whose accumulated_text hit the per-response "
                    "byte cap (one increment per affected response)."
                ),
            ),
        }
        # Self-install as the truncation observer so any ResponseContext
        # whose extend_text() trips the cap funnels into this registry.
        # Idempotent: a second Metrics() instance overwrites the previous
        # observer; tests that need silence call
        # ``signet.core.context.set_truncation_observer(None)``. We import
        # locally to avoid a circular dependency at module-import time
        # (server/__init__ → core/context is fine; the reverse would
        # break since ``core`` must not depend on ``server``).
        from signet.core.context import set_truncation_observer

        set_truncation_observer(self._observe_truncation)

        self._histograms: dict[str, _Histogram] = {
            "signet_check_duration_seconds": _Histogram(
                "signet_check_duration_seconds",
                "Per-check hook latency in seconds, labeled by check / stage / decision.",
                _DEFAULT_DURATION_BUCKETS,
            ),
        }

    def _observe_truncation(self, cap_bytes: int) -> None:
        """Bridge ``ResponseContext`` truncation events into the registry.

        Installed as the module-level observer in
        :mod:`signet.core.context` from :meth:`__init__`. Receives the
        configured cap so dashboards can correlate truncation rates with
        the cap-policy setting that produced them.
        """
        self.inc(
            "signet_response_text_truncated_total",
            {"cap_bytes": str(cap_bytes)},
        )

    def inc(self, name: str, labels: dict[str, str] | None = None, by: float = 1.0) -> None:
        """Bump the counter with the given labels.

        Unknown counter names are silently ignored — callers should not
        be able to crash the request path by mistyping a metric name.
        """
        with self._lock:
            counter = self._counters.get(name)
            if counter is not None:
                counter.inc(labels or {}, by=by)

    def observe_histogram(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        """Record an observation against a labeled histogram.

        Mirrors :meth:`inc` for histograms. Unknown histogram names are
        silently ignored so the request path cannot crash on a typo.
        """
        with self._lock:
            histogram = self._histograms.get(name)
            if histogram is not None:
                histogram.observe(labels or {}, value)

    def render_prometheus(self) -> str:
        """Render the registry in Prometheus text-exposition format."""
        with self._lock:
            lines: list[str] = []
            for counter in self._counters.values():
                lines.extend(counter.render())
            for histogram in self._histograms.values():
                lines.extend(histogram.render())
            # Uptime gauge
            uptime = time.time() - _PROCESS_STARTED_AT
            lines.append("# HELP signet_uptime_seconds Seconds since process start.")
            lines.append("# TYPE signet_uptime_seconds gauge")
            lines.append(f"signet_uptime_seconds {uptime:.1f}")
        return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    """Escape a label value for Prometheus exposition format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


__all__ = ["Metrics"]
