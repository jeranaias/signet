"""Tests for the plugin layer.

Coverage:

* Discovery against an empty environment returns empty dict.
* load_by_name raises informative KeyError for unknown plugin.
* TribunalCheck constructor validation.
* TribunalCheck verdict logic with mocked judges (both-allow, both-block,
  disagree, judge-error).
* SandboxPreviewCheck constructor validation.
* SandboxPreviewCheck dispatch (only_for_tools filter, dryrun-required
  escalation, policy allow/escalate, runner exception fails closed).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from signet.core.context import RequestContext, ResponseContext, ToolCallContext
from signet.core.owner import Owner
from signet.plugins import discover, load_by_name, reset_cache
from signet.plugins.sandbox import (
    SandboxPreviewCheck,
    SandboxResult,
)
from signet.plugins.tribunal import TribunalCheck


def _tool_ctx(tool: str = "send_email", **meta: Any) -> ToolCallContext:
    req = RequestContext(owner=Owner.human("alice"))
    rsp = ResponseContext(request=req)
    return ToolCallContext(
        request=req,
        response=rsp,
        tool_name=tool,
        arguments={"to": "bob@example.com"},
        tool_metadata=meta,
    )


class TestDiscovery:
    def test_empty_environment(self) -> None:
        # Without any external plugin packages installed, discovery
        # returns an empty dict — but it still completes without error.
        reset_cache()
        result = discover(refresh=True)
        # Anything found here came from random installed packages. We
        # only assert the type, not the content.
        assert isinstance(result, dict)

    def test_load_by_name_unknown(self) -> None:
        reset_cache()
        with pytest.raises(KeyError, match="no signet plugin named"):
            load_by_name("definitely-not-installed-7e3a8c")


class TestTribunalConstruction:
    def test_requires_both_urls(self) -> None:
        with pytest.raises(ValueError, match="judge_a_url and judge_b_url"):
            TribunalCheck(judge_a_url="http://a", judge_b_url="")
        with pytest.raises(ValueError, match="judge_a_url and judge_b_url"):
            TribunalCheck(judge_a_url="", judge_b_url="http://b")


class TestTribunalVerdicts:
    @pytest.fixture
    def check(self) -> TribunalCheck:
        return TribunalCheck(judge_a_url="http://a", judge_b_url="http://b")

    def _patch_judges(self, monkeypatch: pytest.MonkeyPatch, verdicts: list[str]) -> None:
        """Replace TribunalCheck._ask_judge with a stub returning verdicts in order."""
        calls: list[int] = []

        async def fake_ask(self, _client, _url, _model, _prompt) -> str:
            idx = len(calls)
            calls.append(idx)
            return verdicts[idx]

        monkeypatch.setattr(TribunalCheck, "_ask_judge", fake_ask)

    async def test_both_allow(self, check: TribunalCheck, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_judges(monkeypatch, ["ALLOW", "ALLOW"])
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_allow

    async def test_both_block(self, check: TribunalCheck, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_judges(monkeypatch, ["BLOCK", "BLOCK"])
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_block

    async def test_disagreement_escalates(
        self, check: TribunalCheck, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_judges(monkeypatch, ["ALLOW", "BLOCK"])
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_escalate
        assert result.metadata["judge_a"] == "ALLOW"
        assert result.metadata["judge_b"] == "BLOCK"

    async def test_disagreement_with_unanimous_block_required(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        check = TribunalCheck(
            judge_a_url="http://a", judge_b_url="http://b", require_unanimous_block=True
        )
        self._patch_judges(monkeypatch, ["ALLOW", "BLOCK"])
        result = await check.inspect_tool_call(_tool_ctx())
        # require_unanimous_block flips disagreement to allow
        assert result.is_allow

    async def test_judge_error_treated_as_block(
        self, check: TribunalCheck, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_post(self, url, *, json):
            raise httpx.ConnectError("network down")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        result = await check.inspect_tool_call(_tool_ctx())
        # Both judges fail → both vote BLOCK → block
        assert result.is_block


class TestSandboxResultSafety:
    def test_ok_with_benign_effect_is_safe(self) -> None:
        r = SandboxResult(ok=True, observed_effect="read 3 rows from users table")
        assert r.is_safe()

    def test_not_ok_is_unsafe(self) -> None:
        r = SandboxResult(ok=False, observed_effect="anything")
        assert not r.is_safe()

    def test_destroy_keyword_flags_unsafe(self) -> None:
        r = SandboxResult(ok=True, observed_effect="would DESTROY 1000 records")
        assert not r.is_safe()


class TestSandboxConstruction:
    def test_no_runner_raises(self) -> None:
        with pytest.raises(ValueError, match="requires a `runner`"):
            SandboxPreviewCheck()


class TestSandboxDispatch:
    @pytest.fixture
    def safe_runner(self):
        async def runner(_tool: str, _args: dict[str, Any]) -> SandboxResult:
            return SandboxResult(ok=True, observed_effect="read-only")

        return runner

    @pytest.fixture
    def destructive_runner(self):
        async def runner(_tool: str, _args: dict[str, Any]) -> SandboxResult:
            return SandboxResult(ok=True, observed_effect="would DELETE table 'users'")

        return runner

    async def test_safe_preview_allows(self, safe_runner) -> None:
        check = SandboxPreviewCheck(runner=safe_runner, require_dryrun_supported=False)
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_allow

    async def test_destructive_preview_escalates(self, destructive_runner) -> None:
        check = SandboxPreviewCheck(runner=destructive_runner, require_dryrun_supported=False)
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_escalate

    async def test_only_for_tools_filter(self, destructive_runner) -> None:
        check = SandboxPreviewCheck(
            runner=destructive_runner,
            only_for_tools=frozenset({"some_other_tool"}),
            require_dryrun_supported=False,
        )
        result = await check.inspect_tool_call(_tool_ctx("send_email"))
        assert result.is_allow  # send_email skipped — not in only_for_tools

    async def test_dryrun_required_but_unsupported_escalates(self, safe_runner) -> None:
        check = SandboxPreviewCheck(runner=safe_runner, require_dryrun_supported=True)
        # tool_metadata defaults to dryrun_supported=False
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_escalate

    async def test_dryrun_supported_proceeds(self, safe_runner) -> None:
        check = SandboxPreviewCheck(runner=safe_runner, require_dryrun_supported=True)
        ctx = _tool_ctx(dryrun_supported=True)
        result = await check.inspect_tool_call(ctx)
        assert result.is_allow

    async def test_runner_exception_fails_closed(self) -> None:
        async def crashing_runner(_tool, _args) -> SandboxResult:
            raise RuntimeError("sandbox container crashed")

        check = SandboxPreviewCheck(runner=crashing_runner, require_dryrun_supported=False)
        result = await check.inspect_tool_call(_tool_ctx())
        assert result.is_block
        assert "RuntimeError" in result.reason

    async def test_registry_is_canonical_source_for_dryrun(self, safe_runner) -> None:
        # v0.1.5 #10: when a registry is supplied, sandbox reads
        # dryrun_supported from there rather than the parallel
        # ToolCallContext.tool_metadata dict. ctx.tool_metadata says
        # False; the registry says True; the registry wins.
        from signet.checks.tool_call_inspector import RiskTier, ToolSpec

        registry = {"send_email": ToolSpec(risk_tier=RiskTier.HIGH, dryrun_supported=True)}
        check = SandboxPreviewCheck(
            runner=safe_runner,
            require_dryrun_supported=True,
            registry=registry,
        )
        # ctx.tool_metadata is empty (default) — without the registry,
        # this would escalate.
        ctx = _tool_ctx("send_email")
        result = await check.inspect_tool_call(ctx)
        assert result.is_allow

    def test_toolspec_as_metadata_round_trip(self) -> None:
        # ToolSpec.as_metadata produces the canonical dict shape that
        # ToolCallContext.tool_metadata expects.
        from signet.checks.tool_call_inspector import RiskTier, ToolSpec

        spec = ToolSpec(risk_tier=RiskTier.HIGH, irreversible=True, dryrun_supported=True)
        meta = spec.as_metadata()
        assert meta == {
            "risk_tier": "high",
            "irreversible": True,
            "dryrun_supported": True,
        }
