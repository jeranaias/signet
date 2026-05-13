"""Round 27 hunt closures — regression coverage for F-R27-* findings.

HIGH:

- ``F-R27-1 ServerConfig constructor bypasses every per-field
  validator``: the dataclass-generated ``__init__`` assigns each field
  via ``__setattr__`` BEFORE ``_post_init_done=True``, so the per-field
  validators in ``__setattr__`` short-circuit for the constructor path.
  Pre-fix, ``ServerConfig(hmac_secret=b"x")`` (1-byte HMAC, defeats
  audit-chain integrity), ``ServerConfig(port=70000)`` (out of range),
  ``ServerConfig(extra_forward_headers=("Auth\\r\\nX-Inject: yes",))``
  (CRLF in header NAME), and every other R11/R13/R15/R17/R21 guard
  slipped through at construction time. The same bypass affected
  ``dataclasses.replace(cfg, port=70000)`` which routes through
  ``__init__``. Post-fix: per-field validators live in the shared
  ``_validate_field`` helper, and ``__post_init__`` re-runs every
  ``_VALIDATED_FIELDS`` validator on the just-constructed instance so
  the constructor and ``replace()`` paths are gated by the same rules
  that already governed direct attribute mutation.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# F-R27-1: per-field validators now fire at construction time
# ---------------------------------------------------------------------------


class TestR27ConstructorBypassClosure:
    """Every R11-R21 per-field validator must fire on ``ServerConfig(...)``."""

    def test_hmac_secret_too_short_rejected_at_construction(self) -> None:
        """1-byte ``hmac_secret`` defeats NIST SP 800-107 §5.3.4 floor."""
        with pytest.raises(ValueError, match="hmac_secret must be at least"):
            ServerConfig(hmac_secret=b"x")

    def test_hmac_secret_empty_bytes_rejected_at_construction(self) -> None:
        """``b""`` is below the 32-byte floor too."""
        with pytest.raises(ValueError, match="hmac_secret must be at least"):
            ServerConfig(hmac_secret=b"")

    def test_hmac_secret_wrong_type_rejected_at_construction(self) -> None:
        """``str`` instead of ``bytes`` is rejected at construction."""
        with pytest.raises(ValueError, match="hmac_secret must be bytes"):
            ServerConfig(hmac_secret="not bytes")  # type: ignore[arg-type]

    def test_hmac_secret_none_still_legal(self) -> None:
        """``None`` is the documented "no audit-chain HMAC" sentinel."""
        cfg = ServerConfig(hmac_secret=None)
        assert cfg.hmac_secret is None

    def test_hmac_secret_valid_32_bytes_accepted(self) -> None:
        """At-floor secret passes both setattr and construction paths."""
        secret = b"x" * 32
        cfg = ServerConfig(hmac_secret=secret)
        assert cfg.hmac_secret == secret

    def test_extra_forward_headers_crlf_rejected_at_construction(self) -> None:
        """CRLF in a header NAME injects upstream-attribution failure (F-R15-7)."""
        with pytest.raises(
            ValueError,
            match=r"extra_forward_headers entry .* is not a valid HTTP/1\.1 header name",
        ):
            ServerConfig(extra_forward_headers=("Authorization\r\nX-Inject: yes",))

    def test_extra_forward_headers_list_rejected_at_construction(self) -> None:
        """List instead of tuple is rejected at construction (R15)."""
        with pytest.raises(ValueError, match="extra_forward_headers must be a tuple"):
            ServerConfig(extra_forward_headers=["Authorization"])  # type: ignore[arg-type]

    def test_extra_forward_headers_non_string_entry_rejected(self) -> None:
        """Non-string entries are rejected at construction."""
        with pytest.raises(ValueError, match="extra_forward_headers entries must be strings"):
            ServerConfig(extra_forward_headers=("Authorization", 42))  # type: ignore[arg-type]

    def test_port_string_rejected_at_construction(self) -> None:
        """``port="foo"`` would crash uvicorn at boot; reject at construction."""
        with pytest.raises(ValueError, match="port must be an int"):
            ServerConfig(port="foo")  # type: ignore[arg-type]

    def test_port_out_of_range_rejected_at_construction(self) -> None:
        """``port=70000`` is out of [0, 65535]."""
        with pytest.raises(ValueError, match=r"port must be in \[0, 65535\]"):
            ServerConfig(port=70000)

    def test_port_bool_rejected_at_construction(self) -> None:
        """``port=True`` (bool subclass of int) is nonsensical; reject."""
        with pytest.raises(ValueError, match="port must be an int"):
            ServerConfig(port=True)

    def test_request_timeout_nan_rejected_at_construction(self) -> None:
        """NaN escapes ``<=0`` guards (F-R15-5); reject at construction."""
        with pytest.raises(ValueError, match="request_timeout_s must be a finite number"):
            ServerConfig(request_timeout_s=float("nan"))

    def test_request_timeout_inf_rejected_at_construction(self) -> None:
        """+Infinity disables the timeout entirely; reject at construction."""
        with pytest.raises(ValueError, match="request_timeout_s must be a finite number"):
            ServerConfig(request_timeout_s=float("inf"))

    def test_request_timeout_negative_rejected_at_construction(self) -> None:
        """Negative timeout is nonsensical."""
        with pytest.raises(ValueError, match="request_timeout_s must be > 0"):
            ServerConfig(request_timeout_s=-1.0)

    def test_max_request_body_bytes_negative_rejected_at_construction(self) -> None:
        """``-100`` is below the 1-byte floor."""
        with pytest.raises(ValueError, match="max_request_body_bytes must be >= 1"):
            ServerConfig(max_request_body_bytes=-100)

    def test_max_request_body_bytes_zero_rejected_at_construction(self) -> None:
        """``0`` is below the 1-byte floor (boundary)."""
        with pytest.raises(ValueError, match="max_request_body_bytes must be >= 1"):
            ServerConfig(max_request_body_bytes=0)

    def test_shutdown_grace_negative_rejected_at_construction(self) -> None:
        """Negative grace-period is rejected at construction."""
        with pytest.raises(ValueError, match="shutdown_grace_seconds must be >= 0"):
            ServerConfig(shutdown_grace_seconds=-1.0)

    def test_shutdown_grace_nan_rejected_at_construction(self) -> None:
        """NaN grace-period would hang shutdown indefinitely."""
        with pytest.raises(ValueError, match="shutdown_grace_seconds must be a finite number"):
            ServerConfig(shutdown_grace_seconds=float("nan"))

    def test_audit_log_path_string_rejected_at_construction(self) -> None:
        """Raw str instead of ``Path`` is rejected at construction."""
        with pytest.raises(ValueError, match=r"audit_log_path must be a pathlib\.Path"):
            ServerConfig(audit_log_path="not a path")  # type: ignore[arg-type]

    def test_audit_log_path_none_accepted_at_construction(self) -> None:
        """``None`` is the documented "in-memory only" sentinel."""
        cfg = ServerConfig(audit_log_path=None)
        assert cfg.audit_log_path is None

    def test_audit_log_path_valid_path_accepted_at_construction(self) -> None:
        """``pathlib.Path`` value passes through cleanly."""
        cfg = ServerConfig(audit_log_path=Path("/tmp/audit.jsonl"))
        assert cfg.audit_log_path == Path("/tmp/audit.jsonl")

    def test_pool_keepalive_negative_rejected_at_construction(self) -> None:
        """Negative keepalive cap silently disables the pool at httpx layer."""
        with pytest.raises(
            ValueError,
            match="upstream_pool_max_keepalive_connections must be >= 1",
        ):
            ServerConfig(upstream_pool_max_keepalive_connections=-5)

    def test_pool_max_connections_zero_rejected_at_construction(self) -> None:
        """``0`` max connections silently disables pooling.

        The explicit pool-ratio cross-check fires FIRST (default
        keepalive=20 > max=0), so the rejection message is the ratio
        message rather than the bare ``>= 1`` floor message. Both
        correctly identify the mis-config; we just match the actually-
        emitted message.
        """
        with pytest.raises(
            ValueError,
            match=(
                r"upstream_pool_max_keepalive_connections .* must be "
                r"<= ServerConfig\.upstream_pool_max_connections"
            ),
        ):
            ServerConfig(upstream_pool_max_connections=0)

    def test_pool_max_connections_zero_via_replace_rejected(self) -> None:
        """``replace(cfg, upstream_pool_max_connections=0)`` is rejected.

        Drives the constructor-bypass path with both pool fields at
        valid values via the original cfg; only the max field changes
        to 0, which trips the cross-field check.
        """
        cfg = ServerConfig()
        with pytest.raises(
            ValueError,
            match=(
                r"upstream_pool_max_keepalive_connections .* must be "
                r"<= ServerConfig\.upstream_pool_max_connections"
            ),
        ):
            dataclasses.replace(cfg, upstream_pool_max_connections=0)

    def test_upstream_url_invalid_scheme_rejected_at_construction(self) -> None:
        """``file://`` upstream is rejected at construction (R9)."""
        with pytest.raises(ValueError, match="upstream_url must use"):
            ServerConfig(upstream_url="file:///etc/openai-key")

    def test_pool_ratio_cross_field_still_caught_at_construction(self) -> None:
        """R19-2 cross-check: keepalive > max is rejected at construction.

        The explicit ``__post_init__`` cross-check fires BEFORE the
        per-field loop so the deterministic ``must be <=`` wording
        wins over the loop's iteration-order-dependent message
        (the per-field loop's pool branch ALSO catches this case --
        belt-and-suspenders -- but with different wording depending
        on whether ``upstream_pool_max_connections`` or
        ``upstream_pool_max_keepalive_connections`` was iterated
        first).
        """
        with pytest.raises(
            ValueError,
            match=(
                r"upstream_pool_max_keepalive_connections .* must be "
                r"<= ServerConfig\.upstream_pool_max_connections"
            ),
        ):
            ServerConfig(
                upstream_pool_max_connections=10,
                upstream_pool_max_keepalive_connections=50,
            )


class TestR27ReplaceBypassClosure:
    """``dataclasses.replace`` routes through ``__init__`` so it must catch the same bypasses."""

    def test_replace_port_out_of_range_rejected(self) -> None:
        """``replace(cfg, port=70000)`` re-runs the constructor validators."""
        cfg = ServerConfig()
        with pytest.raises(ValueError, match=r"port must be in \[0, 65535\]"):
            dataclasses.replace(cfg, port=70000)

    def test_replace_hmac_secret_too_short_rejected(self) -> None:
        """``replace(cfg, hmac_secret=b"x")`` re-runs the HMAC floor check."""
        cfg = ServerConfig()
        with pytest.raises(ValueError, match="hmac_secret must be at least"):
            dataclasses.replace(cfg, hmac_secret=b"x")

    def test_replace_crlf_header_rejected(self) -> None:
        """``replace(cfg, extra_forward_headers=...)`` re-runs the header guard."""
        cfg = ServerConfig()
        with pytest.raises(
            ValueError,
            match=r"extra_forward_headers entry .* is not a valid HTTP/1\.1 header name",
        ):
            dataclasses.replace(cfg, extra_forward_headers=("Authorization\r\nX-Inject: yes",))

    def test_replace_request_timeout_nan_rejected(self) -> None:
        """``replace(cfg, request_timeout_s=nan)`` re-runs the finite check."""
        cfg = ServerConfig()
        with pytest.raises(ValueError, match="request_timeout_s must be a finite number"):
            dataclasses.replace(cfg, request_timeout_s=float("nan"))

    def test_replace_valid_override_succeeds(self) -> None:
        """Sanity: a legal override still works."""
        cfg = ServerConfig()
        cfg2 = dataclasses.replace(cfg, port=9000)
        assert cfg2.port == 9000
        assert cfg.port == 8443  # original unchanged


class TestR27SetattrPathStillWorks:
    """The closure refactor must not break the existing __setattr__ path."""

    def test_setattr_port_out_of_range_still_rejected(self) -> None:
        """``cfg.port = 70000`` after construction still raises."""
        cfg = ServerConfig()
        with pytest.raises(ValueError, match=r"port must be in \[0, 65535\]"):
            cfg.port = 70000
        assert cfg.port == 8443  # R21 F-R21-1: instance state unchanged

    def test_setattr_hmac_secret_too_short_still_rejected(self) -> None:
        """``cfg.hmac_secret = b"x"`` after construction still raises."""
        cfg = ServerConfig()
        with pytest.raises(ValueError, match="hmac_secret must be at least"):
            cfg.hmac_secret = b"x"

    def test_setattr_hmac_secret_none_still_accepted(self) -> None:
        """``cfg.hmac_secret = None`` after construction is still legal."""
        cfg = ServerConfig(hmac_secret=b"x" * 32)
        cfg.hmac_secret = None
        assert cfg.hmac_secret is None

    def test_setattr_crlf_header_still_rejected(self) -> None:
        """``cfg.extra_forward_headers = (CRLF,)`` after construction still raises."""
        cfg = ServerConfig()
        with pytest.raises(
            ValueError,
            match=r"extra_forward_headers entry .* is not a valid HTTP/1\.1 header name",
        ):
            cfg.extra_forward_headers = ("Authorization\r\nX-Inject: yes",)

    def test_setattr_pool_ratio_cross_field_still_rejected(self) -> None:
        """R19-2 cross-check via setattr path still fires."""
        cfg = ServerConfig()
        with pytest.raises(
            ValueError,
            match=(
                r"upstream_pool_max_keepalive_connections .* must be "
                r"<= ServerConfig\.upstream_pool_max_connections"
            ),
        ):
            cfg.upstream_pool_max_keepalive_connections = 200  # default max is 100
