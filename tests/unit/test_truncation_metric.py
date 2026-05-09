"""Tests for v0.1.6 N2 — response-text truncation counter.

When ``ResponseContext.extend_text`` saturates the per-response
``accumulated_text_cap``, the context fires a module-level observer
hook. :class:`signet.server.metrics.Metrics` self-installs as that
observer at construction so the truncation event lands in the
``signet_response_text_truncated_total`` counter.

These tests pin down:

* The first cap-hit on a response increments the counter exactly once.
* Subsequent extensions on the *same* saturated context do not double-
  count (the "first time per response" guard inside ``_mark_truncated``).
* A fresh context's first cap-hit increments the counter again.
* The observer is optional — clearing it (or never installing one)
  must not raise during ``extend_text``.
"""

from __future__ import annotations

import pytest

from signet.core.context import (
    RequestContext,
    ResponseContext,
    set_truncation_observer,
)
from signet.core.owner import Owner
from signet.server.metrics import Metrics


@pytest.fixture(autouse=True)
def _clear_observer_after_test() -> None:
    """Each test installs whatever observer it wants; clear afterwards
    so leakage between tests can't mask bugs."""
    yield
    set_truncation_observer(None)


def _rctx(cap: int) -> ResponseContext:
    rctx = ResponseContext(request=RequestContext(owner=Owner.unresolved()))
    rctx.accumulated_text_cap = cap
    return rctx


def _truncation_total(metrics: Metrics, cap_bytes: int) -> float:
    """Read the counter value for a specific ``cap_bytes`` label."""
    counter = metrics._counters["signet_response_text_truncated_total"]
    return counter.values.get((("cap_bytes", str(cap_bytes)),), 0.0)


class TestTruncationCounter:
    def test_first_saturation_increments_once(self) -> None:
        metrics = Metrics()  # self-installs as observer
        rctx = _rctx(100)

        rctx.extend_text("x" * 200)

        assert rctx.accumulated_text_truncated
        assert len(rctx.accumulated_text) == 100
        assert _truncation_total(metrics, 100) == 1.0

    def test_repeated_extensions_do_not_double_count(self) -> None:
        metrics = Metrics()
        rctx = _rctx(100)

        rctx.extend_text("x" * 200)  # saturate
        rctx.extend_text("more")  # already saturated — no-op text-wise
        rctx.extend_text("still more")  # still no-op

        assert _truncation_total(metrics, 100) == 1.0, (
            "Only the FIRST cap-hit on a context should increment; "
            "subsequent overflow chunks must not inflate the metric."
        )

    def test_fresh_context_increments_again(self) -> None:
        metrics = Metrics()

        first = _rctx(100)
        first.extend_text("x" * 200)

        second = _rctx(100)
        second.extend_text("y" * 200)

        assert _truncation_total(metrics, 100) == 2.0

    def test_distinct_caps_use_distinct_label_values(self) -> None:
        metrics = Metrics()

        small = _rctx(50)
        small.extend_text("a" * 100)

        large = _rctx(500)
        large.extend_text("b" * 1000)

        assert _truncation_total(metrics, 50) == 1.0
        assert _truncation_total(metrics, 500) == 1.0

    def test_under_cap_does_not_increment(self) -> None:
        metrics = Metrics()
        rctx = _rctx(100)

        rctx.extend_text("short")

        assert not rctx.accumulated_text_truncated
        assert _truncation_total(metrics, 100) == 0.0

    def test_exact_fit_does_not_increment(self) -> None:
        metrics = Metrics()
        rctx = _rctx(10)

        rctx.extend_text("0123456789")  # exactly fills, no overflow

        assert not rctx.accumulated_text_truncated
        assert _truncation_total(metrics, 10) == 0.0

    def test_metric_renders_in_prometheus_output(self) -> None:
        metrics = Metrics()
        rctx = _rctx(100)
        rctx.extend_text("x" * 200)

        text = metrics.render_prometheus()

        assert "signet_response_text_truncated_total" in text
        assert 'cap_bytes="100"' in text


class TestTruncationObserverIsOptional:
    def test_observer_unset_does_not_raise(self) -> None:
        # Explicitly clear — simulates the "no metrics in this process"
        # case (CLI tooling, isolated unit tests).
        set_truncation_observer(None)
        rctx = _rctx(10)

        # Must not raise even with no observer installed.
        rctx.extend_text("x" * 50)

        assert rctx.accumulated_text_truncated
        assert rctx.accumulated_text == "xxxxxxxxxx"

    def test_observer_can_be_replaced(self) -> None:
        seen: list[int] = []
        set_truncation_observer(seen.append)

        _rctx(7).extend_text("z" * 20)
        assert seen == [7]

        # Replace with a different sink.
        seen2: list[int] = []
        set_truncation_observer(seen2.append)
        _rctx(13).extend_text("z" * 20)

        assert seen == [7], "Old observer must not fire after replacement."
        assert seen2 == [13]
