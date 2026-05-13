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
from signet.plugins import (
    DiscoveredPlugin,
    discover,
    discover_plugins,
    load_by_name,
    reset_cache,
    resolve,
)
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

    def test_discover_plugins_returns_structured_result(self) -> None:
        # Without plugins installed, returns []. With them, every entry
        # carries the documented fields. We only assert structure here —
        # content is environment-dependent.
        reset_cache()
        result = discover_plugins(refresh=True)
        assert isinstance(result, list)
        for entry in result:
            assert isinstance(entry, DiscoveredPlugin)
            assert entry.group in {
                "signet.checks",
                "signet.adapters",
                "signet.anchors",
            }
            assert isinstance(entry.name, str) and entry.name
            assert isinstance(entry.package, str)
            assert isinstance(entry.package_version, str)
            assert isinstance(entry.target, str) and ":" in entry.target
            assert entry.status in {
                "loaded",
                "incompatible_abi",
                "load_error",
                "duplicate_name",
            }
            assert isinstance(entry.abi_required, int)
            if entry.status == "loaded":
                assert entry.error is None
                assert entry.obj is not None
            else:
                assert entry.error  # non-empty error text on failure
                assert entry.obj is None

    def test_check_abi_version_constant(self) -> None:
        from signet.core.check import CHECK_ABI_VERSION, Check

        assert CHECK_ABI_VERSION == 1
        assert Check.CHECK_ABI_VERSION == 1

    def test_resolve_unknown_plugin_raises(self) -> None:
        reset_cache()
        with pytest.raises(KeyError, match="no signet plugin named"):
            resolve("nonexistent-plugin-9f7c1a")

    def test_resolve_returns_check_class(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from signet.core.check import CHECK_ABI_VERSION, Check
        from signet.core.stage import Stage
        from signet.plugins import discovery as discovery_mod

        class _StubCheck(Check):
            name = "stub_resolve_check"
            stage = Stage.ADMISSION

        stub = DiscoveredPlugin(
            group="signet.checks",
            name="stub_resolve_check",
            package="stub-pkg",
            package_version="0.0.1",
            target="tests.fake:_StubCheck",
            status="loaded",
            abi_declared=CHECK_ABI_VERSION,
            abi_required=CHECK_ABI_VERSION,
            error=None,
            obj=_StubCheck,
        )

        def fake_discover_plugins(*, refresh: bool = False) -> list[DiscoveredPlugin]:
            return [stub]

        monkeypatch.setattr(discovery_mod, "discover_plugins", fake_discover_plugins)
        # resolve() lives in signet.plugins and imports discover_plugins
        # from discovery; patch the import site too.
        import signet.plugins as plugins_pkg

        monkeypatch.setattr(plugins_pkg, "discover_plugins", fake_discover_plugins)

        cls = resolve("stub_resolve_check")
        assert cls is _StubCheck

    def test_duplicate_entry_point_names_flagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Two packages registering the same (group, name) must both
        be marked ``duplicate_name`` with ``duplicate_with`` pointing
        at the OTHER package, and ``obj`` cleared so the silently
        shadowed class can no longer be invoked.
        """
        from signet.core.check import Check
        from signet.core.stage import Stage
        from signet.plugins import discovery as discovery_mod

        class _FirstCheck(Check):
            name = "conflicting_name"
            stage = Stage.ADMISSION

        class _SecondCheck(Check):
            name = "conflicting_name"
            stage = Stage.ADMISSION

        class _FakeDist:
            def __init__(self, name: str, version: str) -> None:
                self.name = name
                self.version = version

        class _FakeEP:
            def __init__(self, name: str, value: str, target, dist) -> None:
                self.name = name
                self.value = value
                self._target = target
                self.dist = dist

            def load(self):
                return self._target

        eps_by_group = {
            "signet.checks": [
                _FakeEP(
                    "conflicting_name",
                    "pkg_one.checks:_FirstCheck",
                    _FirstCheck,
                    _FakeDist("pkg-one", "1.0.0"),
                ),
                _FakeEP(
                    "conflicting_name",
                    "pkg_two.checks:_SecondCheck",
                    _SecondCheck,
                    _FakeDist("pkg-two", "2.0.0"),
                ),
            ],
            "signet.adapters": [],
            "signet.anchors": [],
        }

        def fake_iter(group: str):
            return list(eps_by_group.get(group, []))

        monkeypatch.setattr(discovery_mod, "_iter_entry_points", fake_iter)
        reset_cache()
        result = discover_plugins(refresh=True)

        conflicting = [p for p in result if p.name == "conflicting_name"]
        assert len(conflicting) == 2
        for entry in conflicting:
            assert entry.status == "duplicate_name"
            assert entry.obj is None
            assert entry.error is not None
            assert "conflicting_name" in entry.error
        # duplicate_with must point at the OTHER package, not self.
        first = next(p for p in conflicting if p.package == "pkg-one")
        second = next(p for p in conflicting if p.package == "pkg-two")
        assert first.duplicate_with == ("pkg-two",)
        assert second.duplicate_with == ("pkg-one",)

        # discover() (back-compat dict facade) must NOT hand out a
        # shadowed class for a duplicated name.
        reset_cache()
        monkeypatch.setattr(discovery_mod, "_iter_entry_points", fake_iter)
        check_map = discover(refresh=True)
        assert "conflicting_name" not in check_map

    def test_resolve_refuses_duplicate_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve() on a duplicated entry-point name must raise
        ``RuntimeError`` naming the conflicting packages.
        """
        from signet.plugins import discovery as discovery_mod

        dup_a = DiscoveredPlugin(
            group="signet.checks",
            name="conflicting_name",
            package="pkg-one",
            package_version="1.0.0",
            target="pkg_one.checks:_FirstCheck",
            status="duplicate_name",
            abi_declared=None,
            abi_required=1,
            error="entry-point name 'conflicting_name' is also registered by: pkg-two",
            obj=None,
            duplicate_with=("pkg-two",),
        )
        dup_b = DiscoveredPlugin(
            group="signet.checks",
            name="conflicting_name",
            package="pkg-two",
            package_version="2.0.0",
            target="pkg_two.checks:_SecondCheck",
            status="duplicate_name",
            abi_declared=None,
            abi_required=1,
            error="entry-point name 'conflicting_name' is also registered by: pkg-one",
            obj=None,
            duplicate_with=("pkg-one",),
        )

        def fake_discover_plugins(*, refresh: bool = False) -> list[DiscoveredPlugin]:
            return [dup_a, dup_b]

        import signet.plugins as plugins_pkg

        monkeypatch.setattr(discovery_mod, "discover_plugins", fake_discover_plugins)
        monkeypatch.setattr(plugins_pkg, "discover_plugins", fake_discover_plugins)

        with pytest.raises(RuntimeError, match="duplicate registrations"):
            resolve("conflicting_name")

    def test_single_plugin_no_duplicates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One plugin under a name must remain ``loaded`` — the
        duplicate-detection pass is a no-op for the common case.
        """
        from signet.core.check import Check
        from signet.core.stage import Stage
        from signet.plugins import discovery as discovery_mod

        class _SoloCheck(Check):
            name = "solo_check"
            stage = Stage.ADMISSION

        class _FakeDist:
            def __init__(self, name: str, version: str) -> None:
                self.name = name
                self.version = version

        class _FakeEP:
            def __init__(self, name: str, value: str, target, dist) -> None:
                self.name = name
                self.value = value
                self._target = target
                self.dist = dist

            def load(self):
                return self._target

        eps_by_group = {
            "signet.checks": [
                _FakeEP(
                    "solo_check",
                    "pkg_solo.checks:_SoloCheck",
                    _SoloCheck,
                    _FakeDist("pkg-solo", "1.0.0"),
                ),
            ],
            "signet.adapters": [],
            "signet.anchors": [],
        }

        def fake_iter(group: str):
            return list(eps_by_group.get(group, []))

        monkeypatch.setattr(discovery_mod, "_iter_entry_points", fake_iter)
        reset_cache()
        result = discover_plugins(refresh=True)

        solo = [p for p in result if p.name == "solo_check"]
        assert len(solo) == 1
        assert solo[0].status == "loaded"
        assert solo[0].duplicate_with == ()
        assert solo[0].obj is _SoloCheck

    def test_same_name_in_different_groups_is_not_a_duplicate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``signet.checks: foo`` and ``signet.adapters: foo`` are
        independent registrations. Neither should be flagged as a
        duplicate.
        """
        from signet.core.check import Check
        from signet.core.stage import Stage
        from signet.plugins import discovery as discovery_mod

        class _FooCheck(Check):
            name = "foo"
            stage = Stage.ADMISSION

        # The signet.adapters group has no ABI gate, so any object
        # that EntryPoint.load() returns is recorded as "loaded".
        class _FooAdapter:  # not a Check subclass — and that's fine
            pass

        class _FakeDist:
            def __init__(self, name: str, version: str) -> None:
                self.name = name
                self.version = version

        class _FakeEP:
            def __init__(self, name: str, value: str, target, dist) -> None:
                self.name = name
                self.value = value
                self._target = target
                self.dist = dist

            def load(self):
                return self._target

        eps_by_group = {
            "signet.checks": [
                _FakeEP(
                    "foo",
                    "pkg_a.checks:_FooCheck",
                    _FooCheck,
                    _FakeDist("pkg-a", "1.0.0"),
                ),
            ],
            "signet.adapters": [
                _FakeEP(
                    "foo",
                    "pkg_b.adapters:_FooAdapter",
                    _FooAdapter,
                    _FakeDist("pkg-b", "1.0.0"),
                ),
            ],
            "signet.anchors": [],
        }

        def fake_iter(group: str):
            return list(eps_by_group.get(group, []))

        monkeypatch.setattr(discovery_mod, "_iter_entry_points", fake_iter)
        reset_cache()
        result = discover_plugins(refresh=True)

        foos = [p for p in result if p.name == "foo"]
        assert len(foos) == 2
        for entry in foos:
            assert entry.status == "loaded"
            assert entry.duplicate_with == ()

    def test_incompatible_abi_marked_as_unloaded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from signet.core.check import CHECK_ABI_VERSION, Check
        from signet.core.stage import Stage

        class _FutureCheck(Check):
            name = "future_check"
            stage = Stage.ADMISSION
            CHECK_ABI_VERSION = 99

        stub = DiscoveredPlugin(
            group="signet.checks",
            name="future_check",
            package="future-pkg",
            package_version="0.0.1",
            target="tests.fake:_FutureCheck",
            status="incompatible_abi",
            abi_declared=99,
            abi_required=CHECK_ABI_VERSION,
            error=(
                f"plugin 'future_check' declares CHECK_ABI_VERSION=99; "
                f"signet requires {CHECK_ABI_VERSION}"
            ),
            obj=None,
        )

        def fake_discover_plugins(*, refresh: bool = False) -> list[DiscoveredPlugin]:
            return [stub]

        import signet.plugins as plugins_pkg
        from signet.plugins import discovery as discovery_mod

        monkeypatch.setattr(discovery_mod, "discover_plugins", fake_discover_plugins)
        monkeypatch.setattr(plugins_pkg, "discover_plugins", fake_discover_plugins)

        # Status is reported as incompatible_abi, not loaded.
        plugins = plugins_pkg.discover_plugins()
        assert plugins[0].status == "incompatible_abi"
        assert plugins[0].abi_declared == 99

        # And resolve() refuses with a RuntimeError naming the mismatch.
        with pytest.raises(RuntimeError, match="incompatible_abi"):
            resolve("future_check")


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


# ---------------------------------------------------------------------------
# v0.1.7 P2 plugin polish
# ---------------------------------------------------------------------------


class TestDiscoverPluginsCacheIdentity:
    """C11: ``discover_plugins`` returns the same list object on
    consecutive cached calls but a NEW list object after
    ``refresh=True``. This is documented in the function's docstring;
    the tests pin the contract so a future refactor that, say, returns
    ``list(cache)`` defensively would surface as a docstring mismatch.
    """

    def test_cached_calls_return_same_object(self) -> None:
        reset_cache()
        first = discover_plugins(refresh=True)
        second = discover_plugins()
        # ``is`` — identity, not equality. The cache hands back the
        # exact same list it stashed on the first call.
        assert first is second

    def test_refresh_returns_new_list_object(self) -> None:
        reset_cache()
        first = discover_plugins(refresh=True)
        second = discover_plugins(refresh=True)
        # Contents are equal (same plugins discovered) but the second
        # call rebuilt the cache, so the list object is fresh.
        assert first == second
        assert first is not second

    def test_docstring_mentions_identity_caveat(self) -> None:
        # The doc note this finding adds must actually be in the
        # docstring; otherwise the contract is undocumented.
        doc = discover_plugins.__doc__ or ""
        assert "Identity stability" in doc
        assert "refresh=True" in doc
