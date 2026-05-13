"""Round 21 hunt closures — regression coverage for F-R21-* findings.

This file accumulates regression tests for the Round-21 hunt findings
across the SERVER and CLI / plugin-discovery surfaces.

LOW:

- ``F-R21-1 ServerConfig.__setattr__ persists value before validation``:
  ``__setattr__`` called ``super().__setattr__(name, value)``
  unconditionally before running the validator block. When validation
  raised ``ValueError`` the rejected value was already persisted on the
  instance, so a caller that wraps ``setattr(cfg, k, v)`` in
  ``try/except ValueError: pass`` (plugin frameworks, dynamic-reload
  paths, test harnesses) ended up operating on the rejected value
  despite the loud ``ValueError``. The contract for ``ValueError`` on
  assign is normally "the write didn't happen" (cf. tuples, frozen
  dataclasses, descriptors); the legacy implementation broke it for
  every entry in ``_VALIDATED_FIELDS``.

  Post-fix the validator runs BEFORE ``super().__setattr__`` and the
  value is persisted only when every check passes. A failed assignment
  leaves the prior value intact on the instance.

HIGH (CLI / plugin discovery hunt -- audit_cli.md):

- ``F-R21-1 CliHunt _safe_repr/_safe_str fallback crashes on hostile
  __name__``: the R19 helpers caught ``BaseException`` from
  ``repr(obj)`` / ``str(obj)`` then interpolated
  ``type(exc).__name__`` into the fallback string. But
  ``type(exc).__name__`` is itself attacker-controlled -- a hostile
  metaclass ``__getattribute__`` raising on ``__name__`` propagates a
  fresh exception out of the helper's own except branch, defeating
  exactly the R19 closure. R21 introduces ``_safe_name`` which wraps
  the ``__name__`` access in another ``BaseException`` catch with a
  constant-string fallback, and ``_safe_repr`` / ``_safe_str`` route
  their breadcrumb interpolation through it.

- ``F-R21-2 CliHunt three __name__ accesses bypass the R19 AST sweep``:
  three sites in ``discover_plugins`` interpolated
  ``type(exc).__name__`` (lines 348 + 356) or ``obj.__name__`` (line
  425) directly, side-stepping the R19 ``_safe_repr`` / ``_safe_str``
  helpers entirely. The R19 AST sweep only flagged
  ``Call(repr|str, [Name(plugin_local)])`` -- it did not catch
  attribute-access patterns like ``type(exc).__name__`` or
  ``obj.__name__``. R21 routes all three through ``_safe_name`` and
  extends the AST sweep (see ``test_round19_cli_hunt.py``) to also
  flag bare ``__name__`` / ``__class__`` attribute accesses on
  plugin-controlled locals.
"""

from __future__ import annotations

import ast
import contextlib
import math
import time
from pathlib import Path
from typing import ClassVar

import pytest

from signet.plugins import discovery as plugin_discovery
from signet.plugins.discovery import (
    _safe_name,
    _safe_repr,
    _safe_str,
)
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# LOW -- F-R21-1 __setattr__ validates BEFORE persisting
# ---------------------------------------------------------------------------


class TestF_R21_1_SetattrValidatesBeforePersisting:
    """Every validator in ``ServerConfig._VALIDATED_FIELDS`` must run
    BEFORE ``super().__setattr__``. A failed assignment must leave the
    instance unchanged (the prior value remains readable)."""

    def test_port_rejected_value_does_not_persist(self) -> None:
        """``cfg.port = 99999`` raises; after the raise ``cfg.port`` is
        still the prior valid value, not 99999."""
        cfg = ServerConfig()
        prior = cfg.port
        with pytest.raises(ValueError):
            cfg.port = 99999
        assert cfg.port == prior

    def test_port_negative_value_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.port
        with pytest.raises(ValueError):
            cfg.port = -1
        assert cfg.port == prior

    def test_port_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.port
        with pytest.raises(ValueError):
            cfg.port = "not an int"
        assert cfg.port == prior

    def test_port_bool_does_not_persist(self) -> None:
        """``True`` is an int in Python but is a nonsensical port. The
        validator rejects it; the prior value must remain."""
        cfg = ServerConfig()
        prior = cfg.port
        with pytest.raises(ValueError):
            cfg.port = True
        assert cfg.port == prior

    def test_request_timeout_s_nan_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.request_timeout_s
        with pytest.raises(ValueError):
            cfg.request_timeout_s = float("nan")
        # NaN compares False to itself; check the stored value is finite
        # AND equal to the prior.
        assert math.isfinite(cfg.request_timeout_s)
        assert cfg.request_timeout_s == prior

    def test_request_timeout_s_inf_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.request_timeout_s
        with pytest.raises(ValueError):
            cfg.request_timeout_s = float("inf")
        assert math.isfinite(cfg.request_timeout_s)
        assert cfg.request_timeout_s == prior

    def test_request_timeout_s_zero_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.request_timeout_s
        with pytest.raises(ValueError):
            cfg.request_timeout_s = 0
        assert cfg.request_timeout_s == prior

    def test_max_request_body_bytes_negative_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.max_request_body_bytes
        with pytest.raises(ValueError):
            cfg.max_request_body_bytes = -1
        assert cfg.max_request_body_bytes == prior

    def test_max_request_body_bytes_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.max_request_body_bytes
        with pytest.raises(ValueError):
            cfg.max_request_body_bytes = "lots"
        assert cfg.max_request_body_bytes == prior

    def test_audit_log_path_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.audit_log_path
        with pytest.raises(ValueError):
            cfg.audit_log_path = "not a path"
        assert cfg.audit_log_path == prior

    def test_hmac_secret_short_does_not_persist(self) -> None:
        """A short HMAC secret is rejected; the prior value (``None``
        by default) must remain."""
        cfg = ServerConfig()
        prior = cfg.hmac_secret
        with pytest.raises(ValueError):
            cfg.hmac_secret = b"short"
        assert cfg.hmac_secret == prior

    def test_hmac_secret_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.hmac_secret
        with pytest.raises(ValueError):
            cfg.hmac_secret = "not bytes"  # type: ignore[assignment]
        assert cfg.hmac_secret == prior

    def test_hmac_secret_none_is_persisted_normally(self) -> None:
        """The ``None`` early-return path must still actually persist
        the ``None`` -- not skip the write. Regression guard for the
        Round 21 fix (the legacy ``return`` inside the ``hmac_secret``
        validator bypassed the new persist-at-the-end ``super().__setattr__``)."""
        cfg = ServerConfig()
        cfg.hmac_secret = b"x" * 32  # First set a real value.
        assert cfg.hmac_secret == b"x" * 32
        cfg.hmac_secret = None  # Now clear it.
        assert cfg.hmac_secret is None

    def test_shutdown_grace_seconds_nan_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.shutdown_grace_seconds
        with pytest.raises(ValueError):
            cfg.shutdown_grace_seconds = float("nan")
        assert math.isfinite(cfg.shutdown_grace_seconds)
        assert cfg.shutdown_grace_seconds == prior

    def test_shutdown_grace_seconds_negative_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.shutdown_grace_seconds
        with pytest.raises(ValueError):
            cfg.shutdown_grace_seconds = -1.0
        assert cfg.shutdown_grace_seconds == prior

    def test_extra_forward_headers_crlf_does_not_persist(self) -> None:
        """A CRLF in a header NAME must be rejected; the prior tuple
        must remain. Pre-fix the rejected tuple would persist and a
        caller that catches ``ValueError`` would build an httpx request
        carrying ``Authorization\\r\\nX-Inject: yes`` as a header name."""
        cfg = ServerConfig()
        prior = cfg.extra_forward_headers
        with pytest.raises(ValueError):
            cfg.extra_forward_headers = ("Authorization\r\nX-Inject: yes",)
        assert cfg.extra_forward_headers == prior

    def test_extra_forward_headers_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.extra_forward_headers
        with pytest.raises(ValueError):
            cfg.extra_forward_headers = ["Authorization"]  # type: ignore[assignment]
        assert cfg.extra_forward_headers == prior

    def test_extra_forward_headers_nonstring_entry_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.extra_forward_headers
        with pytest.raises(ValueError):
            cfg.extra_forward_headers = (123,)  # type: ignore[arg-type]
        assert cfg.extra_forward_headers == prior

    def test_upstream_url_bad_scheme_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.upstream_url
        with pytest.raises(ValueError):
            cfg.upstream_url = "gopher://evil"
        assert cfg.upstream_url == prior

    def test_upstream_url_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.upstream_url
        with pytest.raises(ValueError):
            cfg.upstream_url = 12345  # type: ignore[assignment]
        assert cfg.upstream_url == prior

    def test_pool_max_keepalive_above_max_does_not_persist(self) -> None:
        """The headline case from F-R21-1: pre-fix
        ``cfg.upstream_pool_max_keepalive_connections = 9999`` raised,
        but a follow-up read returned ``9999`` -- and httpx.Limits(...)
        built from ``cfg`` carried that 9999 cap. Post-fix the rejected
        value does not persist; the prior cap remains on the instance."""
        cfg = ServerConfig()
        prior_keepalive = cfg.upstream_pool_max_keepalive_connections
        prior_max = cfg.upstream_pool_max_connections
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_keepalive_connections = 9999
        assert cfg.upstream_pool_max_keepalive_connections == prior_keepalive
        assert cfg.upstream_pool_max_connections == prior_max

    def test_pool_max_connections_below_keepalive_does_not_persist(self) -> None:
        """Symmetric direction: lowering ``max_connections`` below the
        current ``keepalive`` cap is rejected without persisting."""
        cfg = ServerConfig()
        cfg.upstream_pool_max_keepalive_connections = 50  # max=100 default
        prior_max = cfg.upstream_pool_max_connections
        prior_keepalive = cfg.upstream_pool_max_keepalive_connections
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_connections = 10
        assert cfg.upstream_pool_max_connections == prior_max
        assert cfg.upstream_pool_max_keepalive_connections == prior_keepalive

    def test_pool_max_connections_negative_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.upstream_pool_max_connections
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_connections = -1
        assert cfg.upstream_pool_max_connections == prior

    def test_pool_max_keepalive_wrong_type_does_not_persist(self) -> None:
        cfg = ServerConfig()
        prior = cfg.upstream_pool_max_keepalive_connections
        with pytest.raises(ValueError):
            cfg.upstream_pool_max_keepalive_connections = "20"  # type: ignore[assignment]
        assert cfg.upstream_pool_max_keepalive_connections == prior

    # -----------------------------------------------------------------
    # Round-trip happy-path guards. The fix is a write-ordering change;
    # successful assignments must still work as before.
    # -----------------------------------------------------------------

    def test_valid_port_assignment_persists(self) -> None:
        cfg = ServerConfig()
        cfg.port = 9090
        assert cfg.port == 9090

    def test_valid_request_timeout_assignment_persists(self) -> None:
        cfg = ServerConfig()
        cfg.request_timeout_s = 30.0
        assert cfg.request_timeout_s == 30.0

    def test_valid_upstream_url_assignment_persists(self) -> None:
        cfg = ServerConfig()
        cfg.upstream_url = "https://api.example.com/v1"
        assert cfg.upstream_url == "https://api.example.com/v1"

    def test_valid_audit_log_path_assignment_persists(self, tmp_path: Path) -> None:
        cfg = ServerConfig()
        target = tmp_path / "audit.jsonl"
        cfg.audit_log_path = target
        assert cfg.audit_log_path == target

    def test_valid_hmac_secret_assignment_persists(self) -> None:
        cfg = ServerConfig()
        secret = b"x" * 32
        cfg.hmac_secret = secret
        assert cfg.hmac_secret == secret

    def test_valid_extra_forward_headers_assignment_persists(self) -> None:
        cfg = ServerConfig()
        cfg.extra_forward_headers = ("Authorization", "X-Custom")
        assert cfg.extra_forward_headers == ("Authorization", "X-Custom")

    def test_valid_pool_caps_assignment_persists(self) -> None:
        cfg = ServerConfig()
        cfg.upstream_pool_max_connections = 200
        cfg.upstream_pool_max_keepalive_connections = 75
        assert cfg.upstream_pool_max_connections == 200
        assert cfg.upstream_pool_max_keepalive_connections == 75

    def test_catch_and_continue_pattern_sees_prior_value(self) -> None:
        """The exact failure mode documented in F-R21-1: a caller wraps
        ``setattr(cfg, k, v)`` in ``try/except ValueError: pass`` (common
        in plugin frameworks / dynamic-reload paths). Pre-fix the
        rejected value persisted silently. Post-fix the prior value
        remains."""
        cfg = ServerConfig()
        prior_keepalive = cfg.upstream_pool_max_keepalive_connections
        prior_port = cfg.port
        prior_url = cfg.upstream_url

        overrides = {
            "upstream_pool_max_keepalive_connections": 9999,
            "port": 99999,
            "upstream_url": "gopher://evil",
        }
        for k, v in overrides.items():
            with contextlib.suppress(ValueError):
                setattr(cfg, k, v)

        assert cfg.upstream_pool_max_keepalive_connections == prior_keepalive
        assert cfg.port == prior_port
        assert cfg.upstream_url == prior_url

    def test_non_validated_field_assignment_still_works(self) -> None:
        """Fields not in ``_VALIDATED_FIELDS`` (e.g. ``host``,
        ``upstream_api_key``) must continue to round-trip through the
        ``__setattr__`` short-circuit path."""
        cfg = ServerConfig()
        cfg.host = "0.0.0.0"
        cfg.upstream_api_key = "sk-test"
        cfg.upstream_label = "test-upstream"
        assert cfg.host == "0.0.0.0"
        assert cfg.upstream_api_key == "sk-test"
        assert cfg.upstream_label == "test-upstream"


# ===========================================================================
# CLI hunt (audit_cli.md) -- F-R21-1 CliHunt and F-R21-2 CliHunt
# ===========================================================================


# ---------------------------------------------------------------------------
# F-R21-1 CliHunt -- _safe_name helper exists and never raises
# ---------------------------------------------------------------------------


class TestF_R21_1_CliHunt_SafeNameHelper:
    """``_safe_name`` returns the ``__name__`` of any object without
    propagating exceptions. Plain inputs return the canonical name;
    hostile metaclass overrides fall back to the constant-string
    breadcrumb (or to a still-valid metaclass-side name, either is
    acceptable -- the property is "no crash")."""

    def test_plain_class_returns_name(self) -> None:
        class MyClass:
            pass

        assert _safe_name(MyClass) == "MyClass"

    def test_plain_instance_returns_class_name(self) -> None:
        """An instance has no ``__name__`` attribute -- the helper
        falls back to ``type(obj).__name__`` so callers can pass an
        exception instance directly and still get a useful breadcrumb."""
        assert _safe_name(RuntimeError("x")) == "RuntimeError"
        assert _safe_name(ValueError("x")) == "ValueError"

    def test_class_with_hostile_metaclass_name_falls_back(self) -> None:
        """A class whose metaclass ``__getattribute__`` raises on
        ``__name__`` must not crash the helper -- discovery still
        completes."""

        class _HostileMeta(type):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom on __name__")
                return type.__getattribute__(cls, name)

        Hostile = _HostileMeta("Hostile", (), {})
        out = _safe_name(Hostile)
        # Either the constant fallback or the metaclass name is
        # acceptable -- the property is "no crash". The metaclass name
        # is actually a more useful breadcrumb when the inner
        # ``type(obj).__name__`` belt-and-suspenders succeeds.
        assert isinstance(out, str)
        assert out  # non-empty

    def test_hostile_exception_instance_does_not_crash(self) -> None:
        """An exception INSTANCE whose class' metaclass raises on
        ``__name__`` must not crash the helper. This is the F-R21-1
        scenario applied directly to the helper."""

        class _HostileExcMeta(type):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom on type(exc).__name__")
                return type.__getattribute__(cls, name)

        HostileExc = _HostileExcMeta("HostileExc", (Exception,), {})
        exc = HostileExc("payload")
        out = _safe_name(exc)
        # Must return SOMETHING (the constant fallback) rather than
        # propagating the RuntimeError.
        assert isinstance(out, str)
        assert out  # non-empty -- constant fallback applies

    def test_custom_fallback_string(self) -> None:
        class _HostileMeta(type):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom")
                return type.__getattribute__(cls, name)

        Hostile = _HostileMeta("Hostile", (Exception,), {})
        # Pass an instance so both __name__ access paths go through
        # the hostile metaclass.
        exc = Hostile("x")
        out = _safe_name(exc, fallback="<custom>")
        assert isinstance(out, str)
        # The function must complete -- either the custom fallback or
        # a derived class name. Either way: no crash.
        assert out


# ---------------------------------------------------------------------------
# F-R21-1 CliHunt -- _safe_repr / _safe_str fallback no longer crashes
# ---------------------------------------------------------------------------


class TestF_R21_1_CliHunt_SafeReprStrFallbackBulletproof:
    """The R19 ``_safe_repr`` / ``_safe_str`` helpers must not crash
    even when the EXCEPTION raised inside ``repr(obj)`` / ``str(obj)``
    has a hostile metaclass ``__getattribute__`` that raises on
    ``__name__``."""

    @staticmethod
    def _make_hostile_exc_class() -> type[Exception]:
        class _HostileExcMeta(type):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom on type(exc).__name__")
                return type.__getattribute__(cls, name)

        return _HostileExcMeta("HostileExc", (Exception,), {})

    def test_safe_repr_with_hostile_exc_name(self) -> None:
        HostileExc = self._make_hostile_exc_class()

        class _Evil:
            def __repr__(self) -> str:
                raise HostileExc("attack")

        out = _safe_repr(_Evil())
        # Pre-R21 this raised RuntimeError out of the helper.
        assert isinstance(out, str)
        assert out.startswith("<repr raised>")

    def test_safe_str_with_hostile_exc_name(self) -> None:
        HostileExc = self._make_hostile_exc_class()

        class _Evil:
            def __str__(self) -> str:
                raise HostileExc("attack")

        out = _safe_str(_Evil())
        # Pre-R21 this raised RuntimeError out of the helper.
        assert isinstance(out, str)
        assert out.startswith("<str raised>")

    def test_safe_repr_with_normal_exc_still_records_breadcrumb(self) -> None:
        """Regression: a plain ``RuntimeError`` must still surface in
        the breadcrumb. The R19 contract is preserved -- R21 only adds
        a defense for the very hostile metaclass case."""

        class _Evil:
            def __repr__(self) -> str:
                raise RuntimeError("boom")

        out = _safe_repr(_Evil())
        assert "<repr raised>" in out
        assert "RuntimeError" in out


# ---------------------------------------------------------------------------
# F-R21-2 CliHunt -- three __name__ sites in discover_plugins are bulletproof
# ---------------------------------------------------------------------------


class TestF_R21_2_CliHunt_HostileNameAccessDoesNotCrashDiscovery:
    """The three ``type(exc).__name__`` / ``obj.__name__`` accesses in
    ``discover_plugins`` are routed through ``_safe_name`` so a hostile
    metaclass cannot abort the discovery walk via ``__name__``."""

    @staticmethod
    def _make_hostile_exc_class() -> type[Exception]:
        class _HostileExcMeta(type):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom on type(exc).__name__")
                return type.__getattribute__(cls, name)

        return _HostileExcMeta("HostileExc", (Exception,), {})

    def test_load_error_with_hostile_exc_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The load-error branch interpolates ``type(exc).__name__``
        into both the log line and the cached error string
        (discovery.py:348, :356). Both sites must survive a hostile
        metaclass ``__getattribute__``."""
        HostileExc = self._make_hostile_exc_class()

        class _EvilEP:
            name = "evil_hostile_exc_name"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise HostileExc("attack")

        class _GoodEP:
            name = "good_after_hostile"
            value = "fakemod:good"
            dist = None

            def load(self) -> object:
                return 42  # non-Check, recorded as load_error downstream

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP(), _GoodEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        # Pre-R21 this raised RuntimeError out of discover_plugins
        # because both the log line and the cached error interpolated
        # ``type(exc).__name__`` directly.
        plugins = plugin_discovery.discover_plugins(refresh=True)

        # Both plugins must be recorded -- the walk did not abort.
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"evil_hostile_exc_name", "good_after_hostile"}

        evil = next(p for p in plugins if p.name == "evil_hostile_exc_name")
        assert evil.status == "load_error"
        assert evil.error is not None
        assert isinstance(evil.error, str)
        assert evil.error  # non-empty

        plugin_discovery.reset_cache()

    def test_non_integer_abi_with_hostile_class_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The non-integer-ABI branch interpolates ``obj.__name__``
        (discovery.py:425). A hostile Check subclass whose metaclass
        raises on ``__name__`` must not crash the walk."""
        from abc import ABCMeta

        from signet.core.check import Check, CheckResult, Stage

        # Mix hostile ``__getattribute__`` into ABCMeta so the Check
        # subclass machinery still resolves abstract methods.
        class _HostileCheckMeta(ABCMeta):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom on obj.__name__")
                return ABCMeta.__getattribute__(cls, name)

        # CHECK_ABI_VERSION must be non-int to hit the F-R21-2 line 425
        # branch. We use a plain string -- the point of this test is
        # the ``obj.__name__`` access at line 425.
        class _EvilCheck(Check, metaclass=_HostileCheckMeta):
            CHECK_ABI_VERSION = "not_an_int"  # type: ignore[assignment]
            name = "_evil_check_hostile_name"
            stage = Stage.ADMISSION

            async def pre_request(self, ctx):  # type: ignore[override]
                return CheckResult.allow()

        class _SecondCheck(Check):
            CHECK_ABI_VERSION = 999
            name = "_second_check_after_evil"
            stage = Stage.ADMISSION

            async def pre_request(self, ctx):  # type: ignore[override]
                return CheckResult.allow()

        class _EvilEP:
            name = "evil_hostile_name_plugin"
            value = "fakemod:evilcheck"
            dist = None

            def load(self) -> type[Check]:
                return _EvilCheck

        class _SecondEP:
            name = "second_plugin_after"
            value = "fakemod:secondcheck"
            dist = None

            def load(self) -> type[Check]:
                return _SecondCheck

        def _fake_iter(group: str) -> list[object]:
            if group == "signet.checks":
                return [_EvilEP(), _SecondEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        # Pre-R21 this raised RuntimeError out of discover_plugins.
        plugins = plugin_discovery.discover_plugins(refresh=True)
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {
            "evil_hostile_name_plugin",
            "second_plugin_after",
        }

        evil = next(p for p in plugins if p.name == "evil_hostile_name_plugin")
        assert evil.status == "incompatible_abi"
        assert evil.error is not None
        assert isinstance(evil.error, str)

        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R21-2 CliHunt -- bounded wall-clock still holds when the helper fires
# ---------------------------------------------------------------------------


class TestF_R21_2_CliHunt_BoundedWallClock:
    """A hostile metaclass that raises on ``__name__`` must complete
    discovery in well under a second -- the R17 / R15 truncation caps
    still apply, plus the R21 ``_safe_name`` short-circuit."""

    def test_hostile_name_does_not_stall(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _HostileExcMeta(type):
            def __getattribute__(cls, name: str):
                if name == "__name__":
                    raise RuntimeError("boom")
                return type.__getattribute__(cls, name)

        HostileExc = _HostileExcMeta("HostileExc", (Exception,), {})

        class _EvilEP:
            name = "evil_hostile_name_perf"
            value = "fakemod:evil"
            dist = None

            def load(self) -> object:
                raise HostileExc("attack")

        def _fake_iter(group: str) -> list[_EvilEP]:
            if group == "signet.checks":
                return [_EvilEP()]
            return []

        monkeypatch.setattr(plugin_discovery, "_iter_entry_points", _fake_iter)
        plugin_discovery.reset_cache()

        t0 = time.perf_counter()
        plugin_discovery.discover_plugins(refresh=True)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"discovery took {elapsed:.3f}s"

        plugin_discovery.reset_cache()


# ---------------------------------------------------------------------------
# F-R21-2 CliHunt -- extended AST sweep also flags Attribute(attr='__name__')
# ---------------------------------------------------------------------------
#
# NOTE: the AST sweep proper (with the F-R19-1 Source Sweep) is extended
# in tests/unit/test_round19_cli_hunt.py per the R21 brief. This class
# is a redundant local guard so a future regression in the discovery
# source trips a test in BOTH files (the original R19 sweep test and
# this R21 attribute-scope extension), keeping the failure mode obvious.


class TestF_R21_2_CliHunt_ExtendedSourceSweep:
    """Source-level audit: every ``__name__`` / ``__class__`` attribute
    access on a plugin-controlled local in ``discovery.py`` MUST go
    through ``_safe_name``. The ``_safe_repr`` / ``_safe_str`` /
    ``_safe_name`` helper bodies are exempt (they contain the ONE
    allowed bare ``__name__`` access).

    Patterns flagged:

    * ``Attribute(value=Name(plugin_local), attr='__name__')`` --
      direct ``obj.__name__``.
    * ``Attribute(value=Attribute(value=Name(plugin_local),
      attr='__class__'), attr='__name__')`` -- ``obj.__class__.__name__``.
    * ``Attribute(value=Call(func=Name('type'), args=[Name(plugin_local)]),
      attr='__name__')`` -- ``type(obj).__name__``.
    """

    _PLUGIN_CONTROLLED_NAMES: ClassVar[set[str]] = {"obj", "declared", "exc"}

    def _helper_ranges(self, tree: ast.AST) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in {
                "_safe_repr",
                "_safe_str",
                "_safe_name",
            }:
                end = node.end_lineno or node.lineno
                ranges.append((node.lineno, end))
        return ranges

    def test_helpers_present(self) -> None:
        source = Path(plugin_discovery.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        helpers = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name in {"_safe_repr", "_safe_str", "_safe_name"}
        }
        assert helpers == {"_safe_repr", "_safe_str", "_safe_name"}, (
            f"missing safe helpers: {helpers}"
        )

    def test_no_bare_name_attribute_on_plugin_values(self) -> None:
        source = Path(plugin_discovery.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        helper_ranges = self._helper_ranges(tree)

        def _in_helper(lineno: int) -> bool:
            return any(lo <= lineno <= hi for lo, hi in helper_ranges)

        def _is_plugin_local(node: ast.AST) -> bool:
            return isinstance(node, ast.Name) and node.id in self._PLUGIN_CONTROLLED_NAMES

        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr not in {"__name__", "__class__"}:
                continue
            if _in_helper(node.lineno):
                continue

            value = node.value
            # Case 1: direct ``obj.__name__`` / ``obj.__class__``.
            if _is_plugin_local(value):
                assert isinstance(value, ast.Name)
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"{value.id}.{node.attr} -- use _safe_name({value.id})"
                )
                continue
            # Case 2: ``type(obj).__name__``.
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "type"
                and value.args
                and _is_plugin_local(value.args[0])
            ):
                inner = value.args[0]
                assert isinstance(inner, ast.Name)
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"type({inner.id}).{node.attr} -- use "
                    f"_safe_name({inner.id})"
                )
                continue
            # Case 3: ``obj.__class__.__name__``.
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "__class__"
                and _is_plugin_local(value.value)
            ):
                inner = value.value
                assert isinstance(inner, ast.Name)
                offenders.append(
                    f"discovery.py:{node.lineno}: bare "
                    f"{inner.id}.__class__.{node.attr} -- use "
                    f"_safe_name({inner.id})"
                )
                continue

        assert not offenders, "\n".join(offenders)
