"""Tests for :class:`signet.core.pipeline.Pipeline`.

Today's coverage focuses on v0.1.6 F5 — the per-check latency
histogram. The Pipeline must:

* Continue to be constructible without a metrics observer (CLI / test
  contexts).
* When a metrics observer is attached, emit one histogram observation
  per dispatched hook, regardless of which hook fired.
* Tag each observation with the right ``check`` / ``stage`` /
  ``decision`` labels — including the timeout-as-block path.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import pytest

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext, ToolCallContext
from signet.core.owner import Owner
from signet.core.pipeline import Pipeline
from signet.core.stage import Stage


class _RecordingObserver:
    """Fake metrics observer that just stashes every observation.

    Mirrors the structural type :class:`Pipeline` expects (see the
    ``_HistogramObserver`` Protocol in ``signet.core.pipeline``); we
    don't import the real ``Metrics`` class here so the test stays
    inside ``signet.core``.
    """

    def __init__(self) -> None:
        self.observations: list[tuple[str, float, dict[str, str]]] = []

    def observe_histogram(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        self.observations.append((name, value, dict(labels or {})))


class _AllowAdmission(Check):
    name = "fake_allow"
    stage = Stage.ADMISSION

    async def pre_request(self, _ctx: RequestContext) -> CheckResult:
        return CheckResult.allow("fake-allowed")


class _BlockAdmission(Check):
    name = "fake_block"
    stage = Stage.ADMISSION

    async def pre_request(self, _ctx: RequestContext) -> CheckResult:
        return CheckResult.block("nope")


class _AllowInspection(Check):
    name = "fake_inspect"
    stage = Stage.INSPECTION

    async def inspect_response_chunk(
        self, _ctx: ResponseContext, _chunk: str
    ) -> CheckResult:
        return CheckResult.allow()


class _AllowCommitment(Check):
    name = "fake_tool"
    stage = Stage.COMMITMENT

    async def inspect_tool_call(self, _ctx: ToolCallContext) -> CheckResult:
        return CheckResult.allow("ok")


class _AllowRecord(Check):
    name = "fake_record"
    stage = Stage.RECORD

    async def post_complete(self, _ctx: ResponseContext) -> CheckResult:
        return CheckResult.allow("done")


class _SlowAdmission(Check):
    name = "fake_slow"
    stage = Stage.ADMISSION
    timeout_seconds = 0.01

    async def pre_request(self, _ctx: RequestContext) -> CheckResult:
        await asyncio.sleep(1.0)
        return CheckResult.allow()


def _ctx() -> RequestContext:
    return RequestContext(
        owner=Owner.unresolved(),
        headers={},
        body={"messages": []},
        path="/v1/chat/completions",
        method="POST",
        client_ip=None,
        session_id=None,
    )


class TestPipelineWithoutMetrics:
    def test_constructs_without_metrics(self) -> None:
        # No metrics, no kwarg — historical contract.
        pipeline = Pipeline(checks=[_AllowAdmission()])
        assert pipeline.checks  # sanity

    @pytest.mark.asyncio
    async def test_runs_pre_request_without_metrics(self) -> None:
        pipeline = Pipeline(checks=[_AllowAdmission()])
        result = await pipeline.pre_request(_ctx())
        assert result.is_allow


class TestPipelineHistogramObservation:
    """F5: per-check duration histogram fires on every hook."""

    @pytest.mark.asyncio
    async def test_pre_request_observes_histogram(self) -> None:
        observer = _RecordingObserver()
        pipeline = Pipeline(checks=[_AllowAdmission()], metrics=observer)
        await pipeline.pre_request(_ctx())

        assert len(observer.observations) == 1
        name, value, labels = observer.observations[0]
        assert name == "signet_check_duration_seconds"
        assert value >= 0.0
        assert labels == {
            "check": "fake_allow",
            "stage": "admission",
            "decision": "allow",
        }

    @pytest.mark.asyncio
    async def test_block_decision_label(self) -> None:
        observer = _RecordingObserver()
        pipeline = Pipeline(checks=[_BlockAdmission()], metrics=observer)
        await pipeline.pre_request(_ctx())

        assert len(observer.observations) == 1
        _, _, labels = observer.observations[0]
        assert labels["decision"] == "block"
        assert labels["check"] == "fake_block"

    @pytest.mark.asyncio
    async def test_inspect_response_chunk_observes(self) -> None:
        observer = _RecordingObserver()
        pipeline = Pipeline(checks=[_AllowInspection()], metrics=observer)
        rctx = ResponseContext(request=_ctx())
        await pipeline.inspect_response_chunk(rctx, "data: {}\n\n")
        assert len(observer.observations) == 1
        assert observer.observations[0][2]["stage"] == "inspection"

    @pytest.mark.asyncio
    async def test_inspect_tool_call_observes(self) -> None:
        observer = _RecordingObserver()
        pipeline = Pipeline(checks=[_AllowCommitment()], metrics=observer)
        rctx = _ctx()
        tool_ctx = ToolCallContext(
            request=rctx,
            response=ResponseContext(request=rctx),
            tool_name="echo",
            arguments={"x": 1},
        )
        await pipeline.inspect_tool_call(tool_ctx)
        assert len(observer.observations) == 1
        assert observer.observations[0][2]["stage"] == "commitment"

    @pytest.mark.asyncio
    async def test_post_complete_observes(self) -> None:
        observer = _RecordingObserver()
        pipeline = Pipeline(checks=[_AllowRecord()], metrics=observer)
        await pipeline.post_complete(ResponseContext(request=_ctx()))
        assert len(observer.observations) == 1
        assert observer.observations[0][2]["stage"] == "record"

    @pytest.mark.asyncio
    async def test_timeout_records_block_decision(self) -> None:
        observer = _RecordingObserver()
        pipeline = Pipeline(checks=[_SlowAdmission()], metrics=observer)
        result = await pipeline.pre_request(_ctx())
        assert result.is_block
        # Timeout still fires exactly one histogram observation, labelled block.
        assert len(observer.observations) == 1
        _, value, labels = observer.observations[0]
        assert labels["decision"] == "block"
        assert labels["check"] == "fake_slow"
        # The elapsed time is at least the timeout itself.
        assert value >= 0.005


class TestSignetAppExposesHistogram:
    """Integration: a real SignetApp emits the histogram into /metrics."""

    def test_metrics_endpoint_includes_histogram_after_request(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import httpx
        from fastapi.testclient import TestClient

        from signet.checks import OwnerResolutionCheck
        from signet.server.app import SignetApp
        from signet.server.config import ServerConfig

        upstream_body: dict[str, Any] = {
            "id": "x",
            "object": "chat.completion",
            "model": "m",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }

        async def fake_post(_self, _url, **_kwargs):  # type: ignore[no-untyped-def]
            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return upstream_body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
        )
        pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True)])
        signet_app = SignetApp(config=config, pipeline=pipeline)
        client = TestClient(signet_app.app)

        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200

        m = client.get("/metrics")
        assert m.status_code == 200
        text = m.text
        # Histogram metadata + at least one bucket line for the firing check.
        assert "# TYPE signet_check_duration_seconds histogram" in text
        assert "signet_check_duration_seconds_bucket" in text
        assert 'check="owner_resolution"' in text
        assert 'stage="admission"' in text
        assert 'decision="allow"' in text
        # The +Inf bucket is always present.
        assert 'le="+Inf"' in text
