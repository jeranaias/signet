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

* ``signet_requests_total{path, decision, status}`` — every request
  that reached :class:`signet.server.app.SignetApp`
* ``signet_pipeline_decisions_total{stage, check, decision}`` — every
  result returned by a check in the pipeline
* ``signet_audit_chain_appends_total`` — total entries written to the
  audit chain
* ``signet_audit_anchor_failures_total{backend}`` — anchor backend
  failures (when external anchoring is configured)
* ``signet_uptime_seconds`` — gauge: seconds since the process started

Counters reset on process restart. For persistent metrics across
restarts, scrape into a long-term store (Prometheus, VictoriaMetrics,
etc.) — that's the standard pattern.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

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
        }

    def inc(self, name: str, labels: dict[str, str] | None = None, by: float = 1.0) -> None:
        """Bump the counter with the given labels.

        Unknown counter names are silently ignored — callers should not
        be able to crash the request path by mistyping a metric name.
        """
        with self._lock:
            counter = self._counters.get(name)
            if counter is not None:
                counter.inc(labels or {}, by=by)

    def render_prometheus(self) -> str:
        """Render the registry in Prometheus text-exposition format."""
        with self._lock:
            lines: list[str] = []
            for counter in self._counters.values():
                lines.extend(counter.render())
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
