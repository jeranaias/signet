"""Tests for signet.core.check (Check ABC + CheckResult)."""

from __future__ import annotations

import pytest

from signet.core.audit import Decision
from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.owner import Owner
from signet.core.stage import Stage


class TestCheckResultConstructors:
    def test_allow_factory(self) -> None:
        r = CheckResult.allow("ok", source="test")
        assert r.decision is Decision.ALLOW
        assert r.reason == "ok"
        assert r.metadata == {"source": "test"}
        assert r.replacement_content is None
        assert r.is_allow

    def test_block_factory(self) -> None:
        r = CheckResult.block("nope", policy="acme.v1")
        assert r.decision is Decision.BLOCK
        assert r.reason == "nope"
        assert r.metadata == {"policy": "acme.v1"}
        assert r.is_block

    def test_redact_factory(self) -> None:
        r = CheckResult.redact("[REDACTED]", "PII present")
        assert r.decision is Decision.REDACT
        assert r.reason == "PII present"
        assert r.replacement_content == "[REDACTED]"
        assert r.is_redact

    def test_escalate_factory(self) -> None:
        r = CheckResult.escalate("needs human review", risk="high")
        assert r.decision is Decision.ESCALATE
        assert r.metadata == {"risk": "high"}
        assert r.is_escalate

    def test_result_is_frozen(self) -> None:
        r = CheckResult.allow()
        with pytest.raises(AttributeError):
            r.reason = "mutated"  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("ctor", "is_allow", "is_block", "is_redact", "is_escalate"),
        [
            (CheckResult.allow, True, False, False, False),
            (lambda: CheckResult.block("x"), False, True, False, False),
            (lambda: CheckResult.redact("x", "y"), False, False, True, False),
            (lambda: CheckResult.escalate("x"), False, False, False, True),
        ],
    )
    def test_predicate_helpers_mutually_exclusive(
        self,
        ctor: object,
        is_allow: bool,
        is_block: bool,
        is_redact: bool,
        is_escalate: bool,
    ) -> None:
        r = ctor()  # type: ignore[operator]
        assert r.is_allow is is_allow
        assert r.is_block is is_block
        assert r.is_redact is is_redact
        assert r.is_escalate is is_escalate


class TestCheckSubclassValidation:
    def test_subclass_without_name_raises_at_definition(self) -> None:
        with pytest.raises(TypeError, match="non-empty `name`"):

            class _BadCheck(Check):
                stage = Stage.ADMISSION
                # name omitted

    def test_subclass_without_stage_raises_at_definition(self) -> None:
        with pytest.raises(TypeError, match="`stage` to a Stage"):

            class _BadCheck(Check):
                name = "bad"
                stage = "admission"  # type: ignore[assignment]  # not a Stage enum

    def test_well_formed_subclass_accepts(self) -> None:
        class _GoodCheck(Check):
            name = "good"
            stage = Stage.ADMISSION

        check = _GoodCheck()
        assert check.name == "good"
        assert check.stage is Stage.ADMISSION


class TestCheckDefaultHooksAreAllow:
    @pytest.fixture
    def check(self) -> Check:
        class _NoOpCheck(Check):
            name = "noop"
            stage = Stage.ADMISSION

        return _NoOpCheck()

    @pytest.fixture
    def ctx(self) -> RequestContext:
        return RequestContext(owner=Owner.unresolved())

    async def test_pre_request_default_is_allow(self, check: Check, ctx: RequestContext) -> None:
        result = await check.pre_request(ctx)
        assert result.is_allow

    async def test_inspect_response_chunk_default_is_allow(
        self, check: Check, ctx: RequestContext
    ) -> None:
        from signet.core.context import ResponseContext

        rctx = ResponseContext(request=ctx)
        result = await check.inspect_response_chunk(rctx, "hello")
        assert result.is_allow

    async def test_inspect_tool_call_default_is_allow(
        self, check: Check, ctx: RequestContext
    ) -> None:
        from signet.core.context import ResponseContext, ToolCallContext

        rctx = ResponseContext(request=ctx)
        tctx = ToolCallContext(request=ctx, response=rctx, tool_name="echo")
        result = await check.inspect_tool_call(tctx)
        assert result.is_allow

    async def test_post_complete_default_is_allow(self, check: Check, ctx: RequestContext) -> None:
        from signet.core.context import ResponseContext

        rctx = ResponseContext(request=ctx)
        result = await check.post_complete(rctx)
        assert result.is_allow


class TestResponseContextAccumulator:
    def test_extend_text_under_cap_appends(self) -> None:
        from signet.core.context import ResponseContext

        rctx = ResponseContext(request=RequestContext(owner=Owner.unresolved()))
        rctx.accumulated_text_cap = 100
        rctx.extend_text("hello")
        rctx.extend_text(" world")
        assert rctx.accumulated_text == "hello world"
        assert not rctx.accumulated_text_truncated

    def test_extend_text_overflow_truncates_and_flags(self) -> None:
        from signet.core.context import ResponseContext

        rctx = ResponseContext(request=RequestContext(owner=Owner.unresolved()))
        rctx.accumulated_text_cap = 10
        rctx.extend_text("0123456789EXTRA")
        assert rctx.accumulated_text == "0123456789"
        assert rctx.accumulated_text_truncated

    def test_extend_text_after_full_drops_silently(self) -> None:
        from signet.core.context import ResponseContext

        rctx = ResponseContext(request=RequestContext(owner=Owner.unresolved()))
        rctx.accumulated_text_cap = 5
        rctx.extend_text("HELLO")
        rctx.extend_text("DROPPED")
        assert rctx.accumulated_text == "HELLO"
        assert rctx.accumulated_text_truncated
