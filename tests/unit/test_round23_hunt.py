"""Round 23 hunt closures — regression coverage for F-R23-* findings.

MED:

- ``F-R23-1 ServerConfig._VALIDATED_FIELDS is per-instance dataclass
  field``: pre-fix ``_VALIDATED_FIELDS`` had a bare ``frozenset[str]``
  annotation inside the ``@dataclass`` body, so the dataclass decorator
  treated it as a normal field. Two failure modes followed:

  1. ``ServerConfig(_VALIDATED_FIELDS=frozenset(), upstream_url=...)``
     was a legal constructor call -- caller-supplied ``**kwargs`` (e.g.
     ``ServerConfig(**unmarshal_yaml(...))``) could neutralize every
     R11-R22 ``__setattr__`` validator silently.
  2. ``cfg._VALIDATED_FIELDS = frozenset()`` on a constructed instance
     wrote an instance attribute that shadowed the class-level gate
     set. Since ``__setattr__`` looked up the gate via
     ``self._VALIDATED_FIELDS`` (instance-first attribute lookup), the
     shadow neutralized the validator.

  Post-fix:

  - ``_VALIDATED_FIELDS`` is annotated ``ClassVar[frozenset[str]]`` so
    the dataclass decorator skips it during field generation (PEP 557).
    Constructor calls passing ``_VALIDATED_FIELDS=...`` raise
    ``TypeError`` (unexpected kwarg).
  - ``__setattr__`` reads via ``type(self)._VALIDATED_FIELDS`` so an
    instance-level shadow assignment cannot bypass the validator gate.
    Even after ``cfg._VALIDATED_FIELDS = frozenset()``, the validator
    still consults the class-level set and rejects bad values.
"""

from __future__ import annotations

from dataclasses import fields
from typing import ClassVar, get_type_hints

import pytest

from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# MED -- F-R23-1 _VALIDATED_FIELDS is a class constant, not a dataclass field
# ---------------------------------------------------------------------------


class TestF_R23_1_ValidatedFieldsIsClassVar:
    """``ServerConfig._VALIDATED_FIELDS`` must be a class-level constant
    (``ClassVar``), NOT a dataclass field. Neither a constructor kwarg
    nor an instance-attribute shadow may bypass the validator gate."""

    def test_validated_fields_is_not_a_dataclass_field(self) -> None:
        """The dataclass decorator must NOT enumerate
        ``_VALIDATED_FIELDS`` among the generated fields."""
        field_names = {f.name for f in fields(ServerConfig)}
        assert "_VALIDATED_FIELDS" not in field_names, (
            "_VALIDATED_FIELDS leaked into the dataclass field list -- "
            "the ClassVar annotation is missing or wrong, so callers can "
            "override it via constructor kwargs or instance assignment "
            "and silently disable the validator gate."
        )

    def test_validated_fields_type_hint_is_classvar(self) -> None:
        """The annotation must resolve to ``ClassVar[frozenset[str]]``
        (or a subscripted equivalent). Regression guard against a future
        edit that drops the ``ClassVar`` wrapper."""
        hints = get_type_hints(ServerConfig, include_extras=False)
        # ``get_type_hints`` resolves ``ClassVar`` to a special form;
        # the simplest robust check is to walk the class annotations
        # raw via ``__annotations__`` and verify the substring.
        raw = ServerConfig.__annotations__["_VALIDATED_FIELDS"]
        # raw may be a string (``from __future__ import annotations``) or
        # a typing object. Coerce to str and check.
        assert "ClassVar" in str(raw), (
            f"_VALIDATED_FIELDS annotation must include ClassVar to "
            f"opt out of dataclass field generation; got {raw!r}"
        )
        # Sanity: the resolved hint round-trips to a ClassVar form.
        resolved = hints.get("_VALIDATED_FIELDS")
        # ``typing.get_type_hints`` strips ``ClassVar`` by default for
        # instance hints but exposes it via ``__class_getitem__`` repr
        # on the wrapped form when present in __annotations__.
        # Belt-and-braces: confirm the class-level value is still a
        # frozenset of strings.
        gate = ServerConfig._VALIDATED_FIELDS
        assert isinstance(gate, frozenset)
        assert all(isinstance(x, str) for x in gate)
        assert "port" in gate
        assert "upstream_url" in gate
        # ``resolved`` may be None when ClassVars are stripped; either
        # way the raw-annotation check above is the load-bearing assertion.
        _ = resolved

    def test_validated_fields_constructor_kwarg_rejected(self) -> None:
        """Passing ``_VALIDATED_FIELDS=`` to the constructor must raise
        ``TypeError`` (unexpected kwarg). Pre-fix the dataclass accepted
        the kwarg and silently neutralized the validator gate."""
        with pytest.raises(TypeError):
            ServerConfig(  # type: ignore[call-arg]
                upstream_url="http://localhost:11434/v1",
                _VALIDATED_FIELDS=frozenset(),
            )

    def test_validated_fields_not_in_instance_dict_by_default(self) -> None:
        """A freshly-constructed instance must NOT carry
        ``_VALIDATED_FIELDS`` in ``__dict__``. Pre-fix the dataclass
        copied the frozenset onto every instance (per-instance field),
        which is both wasteful and the root cause of the bypass."""
        cfg = ServerConfig()
        assert "_VALIDATED_FIELDS" not in cfg.__dict__, (
            f"_VALIDATED_FIELDS leaked into instance __dict__: "
            f"{cfg.__dict__.get('_VALIDATED_FIELDS')!r}. The dataclass "
            f"is still treating it as a field."
        )

    def test_instance_shadow_does_not_bypass_validator(self) -> None:
        """Even after ``cfg._VALIDATED_FIELDS = frozenset()`` (instance
        shadow), the validator must still reject bad values. The fix's
        second leg routes the gate lookup through
        ``type(self)._VALIDATED_FIELDS`` so an instance shadow can't
        override it.

        Note: Python permits the instance-attribute assignment itself
        (you can shadow a ClassVar with an instance attr -- the
        language doesn't prevent it). What matters is that the
        validator-gate lookup ignores the shadow."""
        cfg = ServerConfig()
        prior_port = cfg.port
        # Shadow assignment succeeds (Python doesn't prevent it).
        # ``_VALIDATED_FIELDS`` is not itself in the gate set, so the
        # __setattr__ early-returns via the ``name not in
        # type(self)._VALIDATED_FIELDS`` branch.
        cfg._VALIDATED_FIELDS = frozenset()  # type: ignore[misc]
        # The validator must STILL fire on subsequent bad assignments.
        with pytest.raises(ValueError):
            cfg.port = -1
        assert cfg.port == prior_port, (
            "Instance shadow of _VALIDATED_FIELDS bypassed the port "
            "validator -- __setattr__ is reading the gate via self "
            "instead of type(self)."
        )

    def test_instance_shadow_does_not_bypass_url_validator(self) -> None:
        """Same as above for ``upstream_url`` -- the marquee R11 guard."""
        cfg = ServerConfig()
        prior_url = cfg.upstream_url
        cfg._VALIDATED_FIELDS = frozenset()  # type: ignore[misc]
        with pytest.raises(ValueError):
            cfg.upstream_url = "gopher://evil"
        assert cfg.upstream_url == prior_url

    def test_instance_shadow_does_not_bypass_hmac_validator(self) -> None:
        """Same for ``hmac_secret`` -- the audit-chain integrity guard."""
        cfg = ServerConfig()
        prior_secret = cfg.hmac_secret
        cfg._VALIDATED_FIELDS = frozenset()  # type: ignore[misc]
        with pytest.raises(ValueError):
            cfg.hmac_secret = b"short"
        assert cfg.hmac_secret == prior_secret

    def test_class_level_gate_is_canonical(self) -> None:
        """The class-level ``_VALIDATED_FIELDS`` must remain the canonical
        gate set regardless of any instance-level shenanigans."""
        cfg = ServerConfig()
        # Force an instance shadow to a known-wrong value.
        cfg._VALIDATED_FIELDS = frozenset({"only_this_one"})  # type: ignore[misc]
        # The class-level set is untouched.
        assert "port" in ServerConfig._VALIDATED_FIELDS
        assert "upstream_url" in ServerConfig._VALIDATED_FIELDS
        assert "hmac_secret" in ServerConfig._VALIDATED_FIELDS
        assert "only_this_one" not in ServerConfig._VALIDATED_FIELDS
        # And ``type(cfg)._VALIDATED_FIELDS`` returns the canonical set.
        assert type(cfg)._VALIDATED_FIELDS is ServerConfig._VALIDATED_FIELDS

    def test_no_other_dataclass_body_constants_leak_as_fields(self) -> None:
        """Audit guard: no other class-body constant inside
        ``ServerConfig`` is silently a dataclass field. Any
        non-``ClassVar``-annotated annotation inside the dataclass body
        becomes a field; the only legitimate per-instance fields are
        the documented config knobs.

        Concretely: verify every dataclass field has a sensible default
        for the documented config-knob purpose; the only field starting
        with underscore would be a leaked constant. Pre-fix
        ``_VALIDATED_FIELDS`` showed up in this list; post-fix there
        are zero underscore-prefixed fields."""
        underscore_fields = [f.name for f in fields(ServerConfig) if f.name.startswith("_")]
        assert underscore_fields == [], (
            f"Underscore-prefixed dataclass fields detected: "
            f"{underscore_fields}. These are almost certainly class-body "
            f"constants that should be annotated ``ClassVar`` to opt out "
            f"of dataclass field generation (same class-of-bug as "
            f"F-R23-1)."
        )


class TestF_R23_1_ValidatorGateStillEffectiveAfterShadow:
    """Defense-in-depth: verify the full validator surface still rejects
    every bad value even when an attacker has tried to neutralize the
    gate via instance-shadow."""

    @pytest.fixture
    def cfg_with_shadow(self) -> ServerConfig:
        """Return a config with a poisoned instance-level
        ``_VALIDATED_FIELDS`` shadow."""
        cfg = ServerConfig()
        cfg._VALIDATED_FIELDS = frozenset()  # type: ignore[misc]
        return cfg

    def test_port_validator_still_fires(self, cfg_with_shadow: ServerConfig) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.port = 99999

    def test_request_timeout_validator_still_fires(self, cfg_with_shadow: ServerConfig) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.request_timeout_s = float("nan")

    def test_max_request_body_bytes_validator_still_fires(
        self, cfg_with_shadow: ServerConfig
    ) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.max_request_body_bytes = 0

    def test_shutdown_grace_validator_still_fires(self, cfg_with_shadow: ServerConfig) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.shutdown_grace_seconds = -1

    def test_extra_forward_headers_validator_still_fires(
        self, cfg_with_shadow: ServerConfig
    ) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.extra_forward_headers = ("Authorization\r\nX-Inject: yes",)

    def test_pool_max_connections_validator_still_fires(
        self, cfg_with_shadow: ServerConfig
    ) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.upstream_pool_max_connections = 0

    def test_pool_keepalive_validator_still_fires(self, cfg_with_shadow: ServerConfig) -> None:
        with pytest.raises(ValueError):
            cfg_with_shadow.upstream_pool_max_keepalive_connections = 9999


# Unused import sentinel: keep ``ClassVar`` import live for any future
# parametrized type-form assertions added to this module.
_: type = ClassVar


# ---------------------------------------------------------------------------
# Plugin discovery hostile-metaclass closures (F-R23-1 / F-R23-2 / F-R23-3).
# R20+R22 helpers had gaps R23 surfaced; R24 added _safe_name coercion,
# _safe_getattr widened catch, _safe_isinstance/_safe_issubclass __class__
# defense.
# ---------------------------------------------------------------------------


class TestF_R23_1_SafeNameCoercesHostileReturn:
    def test_returns_string_when_name_returns_raising_str(self) -> None:
        from signet.plugins.discovery import _safe_name

        class _RaisingStr:
            def __str__(self) -> str:
                raise RuntimeError("hostile __str__")

        class _HostileMeta(type):
            def __getattribute__(cls, item):
                if item == "__name__":
                    return _RaisingStr()
                return type.__getattribute__(cls, item)

        class HostileCls(metaclass=_HostileMeta):
            pass

        result = _safe_name(HostileCls)
        assert isinstance(result, str)
        assert result  # truthy

    def test_returns_string_when_name_returns_non_string(self) -> None:
        from signet.plugins.discovery import _safe_name

        class _HostileMeta(type):
            def __getattribute__(cls, item):
                if item == "__name__":
                    return 42
                return type.__getattribute__(cls, item)

        class HostileCls(metaclass=_HostileMeta):
            pass

        result = _safe_name(HostileCls)
        assert isinstance(result, str)


class TestF_R23_2_SafeGetattrCatchesBaseException:
    def test_returns_default_on_runtime_error(self) -> None:
        from signet.plugins.discovery import _safe_getattr

        class _HostileMeta(type):
            def __getattribute__(cls, item):
                if item == "CHECK_ABI_VERSION":
                    raise RuntimeError("hostile metaclass")
                return type.__getattribute__(cls, item)

        class HostileCls(metaclass=_HostileMeta):
            pass

        result = _safe_getattr(HostileCls, "CHECK_ABI_VERSION", default=-1)
        assert result == -1


class TestF_R23_3_SafeIsinstanceDefendsClassProperty:
    def test_returns_fallback_on_raising_class_descriptor(self) -> None:
        from signet.plugins.discovery import _safe_isinstance

        class _Hostile:
            @property
            def __class__(self):  # type: ignore[override]
                raise RuntimeError("hostile __class__")

        obj = _Hostile()
        assert _safe_isinstance(obj, type, fallback=False) is False


# ---------------------------------------------------------------------------
# Audit entry validation (F-R23-5).
# ``AuditEntry.from_dict`` must surface tampered ``entry_id`` as
# ``MalformedAuditEntry`` instead of propagating ``AttributeError``.
# ---------------------------------------------------------------------------


class TestF_R23_5_EntryIdTypeValidated:
    """``AuditEntry.from_dict`` raises ``TypeError`` on non-string
    ``entry_id``; ``JsonlBackend.iter_entries`` routes that through
    ``MalformedAuditEntry`` so the verifier surfaces it as a clean
    ``BreakKind.MALFORMED_LINE`` instead of crashing downstream."""

    @pytest.mark.parametrize(
        "bad_value",
        [["not", "a", "string"], 42, None, {"nested": "dict"}, 3.14],
    )
    def test_non_string_entry_id_rejected(self, bad_value) -> None:
        from signet.core.audit import AuditEntry

        bad: dict = {
            "entry_id": bad_value,
            "ts_ns": 1_000_000_000,
            "owner": {"type": "human", "id": "alice"},
            "decision": "allow",
            "check_name": "test",
            "reason": "",
            "request_fingerprint": "",
            "metadata": {},
            "hmac": "00" * 32,
            "prev_hmac": "00" * 32,
        }
        with pytest.raises(TypeError):
            AuditEntry.from_dict(bad)


# ---------------------------------------------------------------------------
# Compaction marker shape (F-R23-8).
# ``_has_marker_shape`` must reject empty-string ``_marker_signature``.
# ---------------------------------------------------------------------------


class TestF_R23_8_MarkerEmptySignatureRejected:
    def test_empty_signature_string_rejected(self) -> None:
        from signet.audit.compactor import _has_marker_shape
        from signet.core.audit import AuditEntry
        from signet.core.owner import Owner, OwnerType

        entry = AuditEntry(
            entry_id="00000000-0000-0000-0000-000000000000",
            ts_ns=1_000_000_000,
            owner=Owner(owner_type=OwnerType.POLICY, owner_id="compactor"),
            decision="allow",
            check_name="_compaction_marker",
            reason="",
            request_fingerprint="",
            metadata={"_marker_signature": ""},
            hmac="00" * 32,
            prev_hmac="00" * 32,
        )
        assert _has_marker_shape(entry) is False


# ---------------------------------------------------------------------------
# NTFS ADS bypass (F-R23-10).
# ``_reject_windows_reserved_device_name`` must reject ``CON:streamname``
# and other ADS-form paths.
# ---------------------------------------------------------------------------


class TestF_R23_10_NtfsAdsRejected:
    @pytest.mark.parametrize(
        "path_str",
        ["CON:foo", "NUL:bar", "COM1:stream", "PRN:data", "AUX:x"],
    )
    def test_ads_form_rejected(self, path_str: str) -> None:
        from pathlib import Path

        import click

        from signet.cli import _reject_windows_reserved_device_name

        with pytest.raises(click.ClickException):
            _reject_windows_reserved_device_name(Path(path_str))
