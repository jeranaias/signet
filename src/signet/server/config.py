"""ServerConfig -- runtime configuration for the signet proxy.

A single dataclass that holds every dial the server exposes. Construct
explicitly or via :meth:`from_env` to populate from environment variables
matching the canonical ``SIGNET_*`` namespace.

Attributes are intentionally simple types (str, int, bool, Path) so
configs serialize cleanly to YAML / JSON for declarative deployment.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

#: Values treated as truthy by :func:`_parse_bool_env`. Compared
#: case-insensitively after stripping surrounding whitespace, so
#: ``"YES"``, ``" on "``, ``"Enabled"`` all match. The CHANGELOG
#: documents ``SIGNET_SHADOW=1`` as the supported on-switch; this set
#: codifies the same UX across every bool-flag env var so callers don't
#: need to memorize which knob accepts which spelling.
_TRUTHY_ENV_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on", "enabled"})


def _parse_bool_env(value: str) -> bool:
    """Parse an environment-variable value into a bool.

    Accepts ``1``/``true``/``yes``/``on``/``enabled`` as truthy
    (case-insensitive, surrounding whitespace stripped). Anything else
    -- including the empty string and ``"0"``/``"false"``/``"no"`` --
    is falsy. Centralized so every bool-flag env var has identical
    parsing semantics; previously each call site spelled
    ``v.lower() == "true"`` inline, which silently rejected ``"1"``
    even though the CHANGELOG documents ``SIGNET_SHADOW=1`` as valid.
    """
    return value.strip().lower() in _TRUTHY_ENV_VALUES


def _parse_int_env(name: str, value: str) -> int:
    """Parse an int env var, re-raising with the var name on failure.

    Bare ``int(value)`` raises ``ValueError: invalid literal for int()
    with base 10: 'abc'`` which doesn't tell the operator *which*
    SIGNET_* variable was bad (L8). Wrap the conversion so the message
    names the variable.
    """
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer; got {value!r} ({exc})") from exc


def _parse_float_env(name: str, value: str) -> float:
    """Parse a float env var, re-raising with the var name on failure.

    Same rationale as :func:`_parse_int_env` (L8) but for float fields.
    """
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number; got {value!r} ({exc})") from exc


#: Round 15 ``hmac_secret-accepts-trivially-short-secret`` (F-R15-6)
#: closure: HMAC-SHA256 best practice (NIST SP 800-107 §5.3.4)
#: recommends a secret at least equal to the hash output length (32
#: bytes for SHA-256). Shorter secrets defeat the audit-chain integrity
#: goal: a 1-byte secret has ~8 bits of entropy and is guessable in
#: seconds. ``allow_ephemeral_key=False`` was supposed to guarantee
#: audits verify across restarts; without a min-length floor it
#: silently permitted unusable secrets.
_HMAC_SECRET_MIN_BYTES: int = 32


#: Round 15 ``extra_forward_headers-name-validation`` (F-R15-7)
#: closure: RFC 7230 §3.2 ``token`` charset for HTTP/1.1 header names.
#: ``extra_forward_headers`` is operator-controlled but a typo or
#: supply-chain compromise that lands ``Authorization\r\nX-Inject:
#: yes`` into the tuple injects a CRLF in a header NAME, which httpx
#: catches at send time and signet's outer fallback mis-attributes
#: as ``upstream_exception`` 502.
_HEADER_NAME_RE: re.Pattern[str] = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _parse_hex_env(name: str, value: str) -> bytes:
    """Parse a hex-encoded bytes env var, naming the var on failure.

    ``bytes.fromhex`` raises ``ValueError: non-hexadecimal number
    found...`` with no var-name context (L8). Wrap so misconfigurations
    of e.g. SIGNET_HMAC_SECRET are immediately attributable.

    Round 15 ``hmac_secret-accepts-trivially-short-secret`` (F-R15-6)
    closure: enforce the :data:`_HMAC_SECRET_MIN_BYTES` floor on
    ``SIGNET_HMAC_SECRET`` so a hex string like ``"00"`` (decodes to a
    one-byte secret) is rejected at parse time with a clear error
    referencing the NIST SP 800-107 minimum. The matching
    :meth:`ServerConfig.__setattr__` validator enforces the same floor
    on direct assignment / programmatic config so both paths land
    consistently.
    """
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be hex-encoded bytes (e.g. `openssl rand -hex 32`); "
            f"got value of length {len(value)} ({exc})"
        ) from exc
    if name == "SIGNET_HMAC_SECRET" and len(decoded) < _HMAC_SECRET_MIN_BYTES:
        raise ValueError(
            f"{name} must be at least {_HMAC_SECRET_MIN_BYTES} bytes "
            f"(HMAC-SHA256 best practice per NIST SP 800-107 §5.3.4); "
            f"got {len(decoded)} bytes. Generate with "
            f"`openssl rand -hex {_HMAC_SECRET_MIN_BYTES}`."
        )
    return decoded


@dataclass
class ServerConfig:
    """Runtime configuration for :class:`signet.server.app.SignetApp`.

    Attributes:
        upstream_url: Base URL of the upstream LLM service. Must speak
            OpenAI chat-completions wire format. Examples:
            ``"https://api.openai.com/v1"``,
            ``"http://localhost:11434/v1"`` (Ollama),
            ``"http://localhost:8000/v1"`` (vLLM).
        upstream_api_key: Bearer token forwarded to the upstream.
            ``None`` to forward the caller's own ``Authorization`` header.
        host: Bind interface for the proxy. Defaults to ``127.0.0.1`` --
            change to ``0.0.0.0`` for non-loopback exposure (after
            considering the trust model in
            :doc:`docs/architecture`).
        port: Bind port. Defaults to 8443.
        request_timeout_s: Max seconds to wait for an upstream response.
            Streaming requests use this for the connect phase only;
            stream-body timeouts are handled separately.
        audit_log_path: Where to write the HMAC-chained audit log. Set
            to ``None`` to disable persistent audit (in-memory only,
            test harnesses).
        hmac_key_id: Identifier for the active HMAC key. Embedded in
            audit entries and receipts so verifiers know which key to
            use across rotations.
        hmac_secret: Raw HMAC secret. Required when
            ``audit_log_path`` is set. Generated via
            :meth:`signet.audit.keyring.Key.generate` if absent and
            ``allow_ephemeral_key`` is ``True``.
        allow_ephemeral_key: If ``True`` and ``hmac_secret`` is missing,
            generate a fresh key on startup. Useful for dev; never
            enable in production where audits must verify across
            restarts.
        receipt_header_name: HTTP header carrying the per-response
            signed decision summary. Defaults to ``X-Signet-Receipt``.
        emit_receipts: Whether to emit receipts at all. Defaults to
            ``True``; set ``False`` only for debug or when downstream
            cannot handle the additional header.
    """

    upstream_url: str = "http://localhost:11434/v1"
    upstream_api_key: str | None = None
    host: str = "127.0.0.1"
    port: int = 8443
    request_timeout_s: float = 120.0
    audit_log_path: Path | None = None
    hmac_key_id: str = "k1"
    hmac_secret: bytes | None = None
    allow_ephemeral_key: bool = False
    receipt_header_name: str = "X-Signet-Receipt"
    emit_receipts: bool = True
    upstream_label: str | None = None
    """Optional label surfaced in the ``X-Signet-Upstream`` response
    header so callers can finger-point upstream errors vs. signet
    errors at a glance. ``None`` (default) means ``X-Signet-Upstream``
    carries the host portion of ``upstream_url``."""
    cors_allowed_origins: tuple[str, ...] = ()
    """Origins permitted via ``Access-Control-Allow-Origin``. Empty
    (default) disables CORS entirely. Use ``("*",)`` to allow all
    origins (dev only). For browser-based callers in production,
    list the exact origins. signet emits the matching CORS preflight
    + credentialed-response headers via Starlette's CORSMiddleware."""
    cors_allowed_methods: tuple[str, ...] = ("GET", "POST", "OPTIONS")
    """HTTP methods allowed for CORS. Override only if you proxy
    additional methods through an embedded SignetApp."""
    cors_allowed_headers: tuple[str, ...] = (
        "Authorization",
        "Content-Type",
        "X-Commit-Owner",
        "X-Agent-Id",
        "X-Policy-Name",
        "X-Policy-Version",
        "X-Classification",
        "X-Caller-Clearance",
        "X-Signet-Session",
    )
    """Request headers callers can send via CORS. The default set
    covers signet's own attribution + classification headers."""
    cors_allow_credentials: bool = False
    """Whether to set ``Access-Control-Allow-Credentials: true``.
    Required when callers send cookies or HTTP auth via CORS;
    incompatible with ``cors_allowed_origins=("*",)`` per the spec."""
    shutdown_grace_seconds: float = 10.0
    """On lifespan shutdown (SIGTERM, uvicorn graceful stop), wait up
    to this many seconds for in-flight streaming responses to finish
    before tearing down the upstream HTTP client. Streams that don't
    complete by the deadline are abandoned; their audit rows are
    still written by the streaming generator's finally block. Set 0
    to skip the grace period (production should keep this > 0)."""
    max_request_body_bytes: int = 4 * 1024 * 1024
    """Hard cap on inbound request body size. Anything larger gets a
    413 before signet attempts to parse it. Default 4 MiB covers
    typical chat-completion bodies (a few-thousand-message conversation
    fits easily) and refuses obvious DoS payloads. Raise if you have
    legitimate use of long contexts as raw text in the request body."""
    strict_error_redaction: bool = True
    """When True (default), 4xx refusal bodies are coarsened to
    ``{"error": "refused", "correlation_id": "<entry_id>"}`` so the
    public response does not name the firing check, its reason, or the
    rule that tripped. The full detail still lands in the audit chain
    and the ``X-Signet-Receipt`` header -- incident response correlates
    via the entry ID. Turn off (``--no-strict-error-redaction`` or set
    ``False``) only for development, debugging integration issues, or
    deployments behind a fully-trusted client. ``signet serve --dev``
    flips this off automatically."""
    shadow: bool = False
    """When True, ADMISSION + INSPECTION + COMMITMENT block and escalate
    decisions are converted to allow at the response layer; the audit
    chain still records the original decision (with metadata.shadow=True),
    the response carries X-Signet-Shadow-* headers describing the
    would-be refusal, and the signet_shadow_would_have_blocked_total
    counter increments. Operators pilot signet in shadow mode against
    production traffic to see what would be blocked before flipping
    enforcement on."""
    realtime_enabled: bool = True
    """Whether to register the ``/v1/realtime`` WebSocket route.
    Defaults to ``True`` -- the route is always registered and FastAPI
    does not pre-allocate handlers, so deployments that never receive
    realtime traffic incur no cost. Set ``False`` to skip route
    registration entirely; deployments that want a hard guarantee
    against an opened WebSocket can flip this off. The HTTP routes
    are unaffected either way. When disabled, the route is still
    registered as a stub that immediately closes any incoming
    connection with code 1011 + reason ``"realtime endpoint disabled
    in config"`` so operators can distinguish "endpoint disabled" from
    "endpoint never registered" / network errors (R3)."""
    inspect_all_sse_lines: bool = True
    """Feed ``event:``, ``id:``, ``retry:``, and ``:`` (comment)
    lines from upstream SSE frames into INSPECTION's accumulated text
    (S6). The SSE spec lets non-``data:`` lines smuggle text past
    classification scanners that only look at ``data:`` payloads --
    e.g. ``event: foo\\ndata: bar\\n\\n`` could carry a classification
    marker on the ``event:`` line that ScopeDriftCheck never sees.

    Round 9 ``sse-non-data-fields-default-skip`` closure flipped the
    default from ``False`` to ``True``: the cost is a few extra
    ``startswith`` checks per line; the bypass it closes is a
    side-channel smuggle of classified bytes via ``retry:`` /
    ``event:`` / ``id:`` fields that operators are unlikely to know
    they need to opt into. Deployments that explicitly want the old
    OpenAI-protocol-strict behavior can set this to ``False``."""

    # Forwarded fields the user can tune via env-var: see _ENV_KEYS below.
    extra_forward_headers: tuple[str, ...] = field(
        default_factory=lambda: ("Authorization", "OpenAI-Beta", "OpenAI-Organization")
    )
    """Headers from the inbound request that are forwarded to the
    upstream verbatim. Owner-resolution and classification headers are
    consumed by signet itself and are NOT forwarded by default."""

    upstream_pool_max_connections: int = 100
    """Round 17 ``httpx-pool-limits-not-tunable`` (F-R17-3) closure:
    cap on simultaneous upstream connections held by the shared
    ``httpx.AsyncClient`` pool. Matches the legacy httpx default so the
    field is a no-op for deployments that don't tune it. Raise for
    high-fanout SSE traffic; lower on constrained hosts. Connections
    over the cap queue rather than fail."""

    upstream_pool_max_keepalive_connections: int = 20
    """Round 17 ``httpx-pool-limits-not-tunable`` (F-R17-3) closure:
    cap on idle keep-alive connections in the upstream pool. Matches
    the legacy httpx default. Connections past this cap are closed
    rather than retained for reuse; raising the cap trades memory for
    latency under sustained load."""

    def __post_init__(self) -> None:
        """Validate fields that have whole-shape constraints.

        Round 9 ``upstream_url-config-accepts-arbitrary-schemes``
        closure: ``upstream_url`` was previously a free-form string
        accepting ``file://``, ``javascript:``, ``gopher://``,
        ``data:`` etc. At request time ``httpx`` rejected
        non-HTTP(S) schemes with ``UnsupportedProtocol`` which signet
        funneled into a 502 ``upstream_protocol_violation`` audit row
        -- defense in depth, but a misconfigured deployment that
        points ``SIGNET_UPSTREAM_URL=file:///etc/openai-key`` (operator
        typo) silently dashboards a 100% 502 rate until someone reads
        the logs. Fail fast at boot instead: only ``http://`` and
        ``https://`` are accepted; anything else raises ``ValueError``
        naming the offending scheme.

        Round 11 ``from_env-whitespace-and-control-bytes`` closure
        scopes the control-byte rejection to :meth:`from_env` (the
        operator-typed-env-var path) rather than to direct
        constructions, so callers that intentionally hand a URL with
        non-letter bytes (CLI sanitization tests, dev harnesses) still
        round-trip cleanly through the constructor.

        Round 27 ``ServerConfig-constructor-bypasses-per-field-validators``
        (F-R27-1) closure: the dataclass-generated ``__init__`` assigns
        each field via ``__setattr__`` BEFORE ``_post_init_done=True``,
        so the per-field validators in ``__setattr__`` short-circuit
        for the constructor path. Pre-fix, ``ServerConfig(hmac_secret=b"x")``,
        ``ServerConfig(port=70000)``,
        ``ServerConfig(extra_forward_headers=("Auth\\r\\nX-Inject: yes",))``
        and every other R11/R13/R15/R17/R21 guard slipped through at
        construction time (and the same bypass affected
        ``dataclasses.replace(cfg, port=70000)`` which routes through
        ``__init__``). Closure: re-run every ``_VALIDATED_FIELDS``
        validator on the just-constructed instance via the shared
        :meth:`_validate_field` helper. The explicit pool-ratio
        cross-check runs BEFORE the per-field loop so its
        deterministic ``must be <=`` wording wins over the loop's
        frozenset-iteration-order-dependent wording for the ratio
        case.
        """
        # Round 19 ``pool-keepalive-ratio-not-sanity-checked`` (F-R19-2)
        # closure: cross-field check at construction time. The per-field
        # ``_validate_field`` re-validation loop below ALSO catches the
        # ratio mis-config (via the pool branch's peer comparison
        # against the now-finalized peer field), but that loop's
        # iteration order is a frozenset traversal -- non-deterministic
        # message wording depending on which pool field is visited
        # first. Run the explicit ``keepalive > max`` cross-check FIRST
        # so the constructor-bypass path always emits the same
        # ``must be <=`` wording that the R19-2 regression tests
        # expect. Both pool fields hold their final post-``__init__``
        # values here (dataclass-generated assignments completed).
        if self.upstream_pool_max_keepalive_connections > self.upstream_pool_max_connections:
            raise ValueError(
                f"ServerConfig.upstream_pool_max_keepalive_connections "
                f"({self.upstream_pool_max_keepalive_connections}) must be "
                f"<= ServerConfig.upstream_pool_max_connections "
                f"({self.upstream_pool_max_connections}); httpx silently "
                f"clamps the keepalive cap to max_connections, so the "
                f"larger value is a hidden mis-config."
            )
        # Round 27 F-R27-1: re-run every per-field validator on the
        # just-constructed instance. The shared ``_validate_field``
        # helper is the single source of truth shared with
        # ``__setattr__``; calling it here closes the constructor
        # bypass for every R11-R21 guard at once. The explicit
        # pool-ratio cross-check above runs FIRST so its
        # deterministic wording wins over the per-field loop's
        # iteration-order-dependent wording for the ratio case.
        # ``sorted(...)`` gives a stable iteration order so any
        # future failure surfaces consistently across Python runs.
        for field_name in sorted(type(self)._VALIDATED_FIELDS):
            self._validate_field(field_name, getattr(self, field_name))
        # Flip the flag last so :meth:`__setattr__` starts re-running
        # validation on any subsequent ``cfg.upstream_url = ...`` write.
        # The flag is set via ``object.__setattr__`` to bypass our own
        # ``__setattr__`` (which would otherwise short-circuit on the
        # name match against a non-string sentinel).
        object.__setattr__(self, "_post_init_done", True)

    # Fields that ``__setattr__`` re-validates on every mutation. Each
    # entry maps the field name to a validator callable that raises
    # ``ValueError`` (or ``TypeError`` -- wrapped to ValueError below)
    # if ``value`` is not a legal value for the field. Round 13
    # ``setattr-validates-only-upstream_url`` closure extends the R11
    # scheme guard from ``upstream_url`` alone to the full set of
    # fields that ``from_env`` parses, so a typo / wrong type on
    # ``cfg.port = "not an int"``, ``cfg.max_request_body_bytes = -1``,
    # ``cfg.audit_log_path = "not a path"``, or ``cfg.hmac_secret =
    # "not bytes"`` fails at the assignment line rather than at
    # uvicorn boot or under load.
    # Round 23 ``_VALIDATED_FIELDS-is-per-instance-dataclass-field``
    # (F-R23-1) closure: annotate as ``ClassVar`` so the dataclass
    # decorator skips this during field generation. Pre-fix the bare
    # ``frozenset[str]`` annotation made the dataclass treat this as a
    # normal field, so ``ServerConfig(_VALIDATED_FIELDS=frozenset(),
    # upstream_url=...)`` was a legal constructor call that silently
    # neutralized every R11-R22 validator. ``ClassVar`` is the explicit
    # dataclass opt-out (PEP 557). Paired with the
    # ``type(self)._VALIDATED_FIELDS`` lookup in ``__setattr__`` so an
    # instance-level shadow assignment cannot bypass the validator gate
    # set either.
    _VALIDATED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "upstream_url",
            "port",
            "request_timeout_s",
            "max_request_body_bytes",
            "audit_log_path",
            "hmac_secret",
            "shutdown_grace_seconds",
            # Round 15 ``extra_forward_headers-name-validation``
            # (F-R15-7) closure: validate header NAMES against the
            # RFC 7230 token charset so a typo / supply-chain
            # compromise that lands a CRLF in a name is refused at
            # the assignment line rather than at h11 wire-send.
            "extra_forward_headers",
            # Round 17 ``httpx-pool-limits-not-tunable`` (F-R17-3)
            # closure: upstream connection-pool caps must be positive
            # ints. ``0`` or a negative value silently disables the
            # pool at httpx layer and degrades to per-request
            # connect, which is an operability foot-gun -- validate
            # at the assignment line.
            "upstream_pool_max_connections",
            "upstream_pool_max_keepalive_connections",
        }
    )

    def _validate_field(self, name: str, value: object) -> None:
        """Validate one guarded field's would-be value, raise on failure.

        Shared helper called from BOTH :meth:`__setattr__` (per-mutation
        re-validation) and :meth:`__post_init__` (Round 27 F-R27-1
        constructor-bypass closure). Raises ``ValueError`` on any
        invalid shape; leaves the instance untouched (callers persist
        only after a successful return).

        Cross-field checks (pool keepalive ratio) compare ``value``
        against the *current* peer field on ``self`` -- in the
        ``__setattr__`` path the peer is the still-prior value (we
        haven't persisted yet, per Round 21 F-R21-1); in the
        ``__post_init__`` path the peer is the finalized constructor
        value (all dataclass-generated assignments completed before
        we run).
        """
        if name == "upstream_url":
            from urllib.parse import urlparse

            if not isinstance(value, str):
                raise ValueError(
                    f"ServerConfig.upstream_url must be a string; got {type(value).__name__}"
                )
            parsed = urlparse(value)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"ServerConfig.upstream_url must use http:// or https://; "
                    f"got scheme {parsed.scheme!r} "
                    f"(upstream_url={value!r}). "
                    f"Supported schemes: http, https."
                )
        elif name == "port":
            # ``isinstance(value, bool)`` excludes True/False (which
            # are ints in Python but are nonsensical port values).
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"ServerConfig.port must be an int; got {type(value).__name__}")
            if not (0 <= value <= 65535):
                raise ValueError(f"ServerConfig.port must be in [0, 65535]; got {value}")
        elif name == "request_timeout_s":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"ServerConfig.request_timeout_s must be a number; got {type(value).__name__}"
                )
            # Round 15 ``nan-inf-accepted-in-timeouts`` (F-R15-5)
            # closure: NaN compares False to itself so the legacy
            # ``value <= 0`` guard let NaN slip through; +Infinity
            # similarly tested ``> 0`` and disabled the timeout
            # entirely. Both propagate into httpx's ``Timeout(...)``
            # and produce undefined behavior under load (immediate
            # timeout, infinite hang, or TypeError on internal
            # comparison). Reject non-finite values explicitly with
            # a clear error so misconfiguration fails fast at config
            # construction rather than under load.
            if not math.isfinite(value):
                raise ValueError(
                    f"ServerConfig.request_timeout_s must be a finite number; got {value!r}"
                )
            if value <= 0:
                raise ValueError(f"ServerConfig.request_timeout_s must be > 0; got {value}")
        elif name == "max_request_body_bytes":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(
                    f"ServerConfig.max_request_body_bytes must be an int; "
                    f"got {type(value).__name__}"
                )
            if value < 1:
                raise ValueError(f"ServerConfig.max_request_body_bytes must be >= 1; got {value}")
        elif name == "audit_log_path":
            if value is not None and not isinstance(value, Path):
                raise ValueError(
                    f"ServerConfig.audit_log_path must be a pathlib.Path "
                    f"or None; got {type(value).__name__}"
                )
        elif name == "hmac_secret":
            if value is None:
                # ``None`` is a legal value (no audit-chain HMAC); skip
                # the bytes-shape + length-floor checks below. The
                # ``__setattr__`` caller persists ``None`` directly;
                # ``__post_init__`` re-validation just no-ops on None.
                return
            if not isinstance(value, (bytes, bytearray)):
                raise ValueError(
                    f"ServerConfig.hmac_secret must be bytes or None; got {type(value).__name__}"
                )
            # Round 15 ``hmac_secret-accepts-trivially-short-secret``
            # (F-R15-6) closure: HMAC-SHA256 best practice (NIST SP
            # 800-107 §5.3.4) recommends a secret at least equal to
            # the hash output length. Pre-fix ``b""`` / ``b"x"`` were
            # silently accepted, defeating audit-chain integrity (an
            # attacker who reads the chain HEAD can guess a 1-byte
            # secret in seconds). Reject anything below the floor
            # with a clear error pointing at ``openssl rand -hex 32``.
            if len(value) < _HMAC_SECRET_MIN_BYTES:
                raise ValueError(
                    f"ServerConfig.hmac_secret must be at least "
                    f"{_HMAC_SECRET_MIN_BYTES} bytes (HMAC-SHA256 best "
                    f"practice per NIST SP 800-107 §5.3.4); got "
                    f"{len(value)} bytes. Generate a strong secret "
                    f"with `openssl rand -hex {_HMAC_SECRET_MIN_BYTES}`."
                )
        elif name == "shutdown_grace_seconds":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"ServerConfig.shutdown_grace_seconds must be a number; "
                    f"got {type(value).__name__}"
                )
            # Round 15 ``nan-inf-accepted-in-timeouts`` (F-R15-5)
            # closure: see the ``request_timeout_s`` comment above.
            # ``shutdown_grace_seconds`` flows into ``asyncio.wait_for``
            # and the same NaN/Inf semantics apply -- propagating
            # either into the lifespan shutdown path causes a stuck
            # process at SIGTERM.
            if not math.isfinite(value):
                raise ValueError(
                    f"ServerConfig.shutdown_grace_seconds must be a finite number; got {value!r}"
                )
            if value < 0:
                raise ValueError(f"ServerConfig.shutdown_grace_seconds must be >= 0; got {value}")
        elif name in (
            "upstream_pool_max_connections",
            "upstream_pool_max_keepalive_connections",
        ):
            # Round 17 ``httpx-pool-limits-not-tunable`` (F-R17-3)
            # closure: positive int. Reject bool / non-int / non-
            # positive values at the assignment line so a typo'd
            # ``cfg.upstream_pool_max_connections = "100"`` or ``-1``
            # fails fast rather than at httpx pool construction.
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"ServerConfig.{name} must be an int; got {type(value).__name__}")
            if value < 1:
                raise ValueError(f"ServerConfig.{name} must be >= 1; got {value}")
            # Round 19 ``pool-keepalive-ratio-not-sanity-checked``
            # (F-R19-2) closure: cross-field check. httpx 0.28.1
            # silently accepts ``max_keepalive_connections >
            # max_connections`` at ``Limits(...)`` construction; in
            # practice the active cap is ``max_connections`` so the
            # operator's intended keepalive count is quietly clamped
            # to the smaller value. Pure operability foot-gun -- not a
            # security issue, but a hidden mis-config the operator
            # almost certainly didn't intend. Reject at the assignment
            # line. The peer-field lookup compares the *would-be* value
            # against the *current* peer (Round 21 F-R21-1 closure
            # changed write ordering so this branch runs BEFORE
            # ``super().__setattr__``, hence ``self.<name>`` still holds
            # the prior value -- which is the value we want to compare
            # against the incoming ``value``).
            if name == "upstream_pool_max_keepalive_connections":
                peer = self.upstream_pool_max_connections
                if value > peer:
                    raise ValueError(
                        f"ServerConfig.upstream_pool_max_keepalive_connections "
                        f"({value}) must be <= "
                        f"ServerConfig.upstream_pool_max_connections "
                        f"({peer}); httpx silently clamps the keepalive cap "
                        f"to max_connections, so the larger value is a "
                        f"hidden mis-config."
                    )
            else:  # name == "upstream_pool_max_connections"
                peer = self.upstream_pool_max_keepalive_connections
                if peer > value:
                    raise ValueError(
                        f"ServerConfig.upstream_pool_max_connections "
                        f"({value}) must be >= "
                        f"ServerConfig.upstream_pool_max_keepalive_connections "
                        f"({peer}); httpx silently clamps the keepalive cap "
                        f"to max_connections, so lowering max_connections "
                        f"below the existing keepalive cap is a hidden "
                        f"mis-config."
                    )
        elif name == "extra_forward_headers":
            # Round 15 ``extra_forward_headers-name-validation``
            # (F-R15-7) closure: the value-side R13 closure
            # (``_header_value_is_safe``) validates inbound header
            # VALUES at admit time; the operator-controlled tuple of
            # header NAMES went unchecked. A typo / supply-chain
            # compromise that lands ``"Authorization\r\nX-Inject: yes"``
            # in the tuple injects a CRLF into a header NAME, which
            # httpx catches at send time and signet's outer fallback
            # mis-attributes as ``upstream_exception`` 502 -- the
            # same wrong-attribution failure mode R13 retired for
            # values. Validate NAMES against RFC 7230 §3.2 ``token``
            # charset at the config layer so the misconfiguration
            # fails fast.
            if not isinstance(value, tuple):
                raise ValueError(
                    f"ServerConfig.extra_forward_headers must be a tuple; "
                    f"got {type(value).__name__}"
                )
            for entry in value:
                if not isinstance(entry, str):
                    raise ValueError(
                        f"ServerConfig.extra_forward_headers entries must "
                        f"be strings; got {type(entry).__name__} "
                        f"({entry!r})"
                    )
                if not _HEADER_NAME_RE.match(entry):
                    raise ValueError(
                        f"ServerConfig.extra_forward_headers entry "
                        f"{entry!r} is not a valid HTTP/1.1 header name "
                        f"(RFC 7230 §3.2 token charset: "
                        f"[!#$%&'*+\\-.^_`|~0-9A-Za-z]+)"
                    )

    def __setattr__(self, name: str, value: object) -> None:
        """Re-validate guarded fields on every mutation.

        Round 11 ``ServerConfig-mutability-bypasses-scheme-validation``
        closure (initial scope: ``upstream_url`` only): pre-fix the
        boot-time scheme guard could be bypassed by reassigning
        ``cfg.upstream_url`` post-``__post_init__``. The clean fix would
        be ``@dataclass(frozen=True)``, but that breaks the env-override
        mutation path (:meth:`from_env` writes each ``SIGNET_*``
        override onto the constructed instance) and embedders / CLI
        flag-override paths that the project intentionally supports.
        Validate on every mutation instead.

        Round 13 ``setattr-validates-only-upstream_url`` closure extends
        the validation to every field that has type / range / shape
        constraints in :meth:`__post_init__` or :meth:`from_env`. Pre-
        fix ``cfg.port = "not an int"``,
        ``cfg.max_request_body_bytes = -1``,
        ``cfg.audit_log_path = "not a path"``, or
        ``cfg.hmac_secret = "not bytes"`` silently succeeded and the
        misconfiguration only surfaced at uvicorn boot (confusing
        traceback) or under load. Each guarded field now raises
        ``ValueError`` at the assignment line.

        See :attr:`_VALIDATED_FIELDS` for the closed set.

        Mirrors :meth:`__post_init__`'s scope: the embedded-control-
        byte rejection is scoped to :meth:`from_env` (operator env
        input), NOT to direct mutation, so embedders that hand a CLI-
        sanitized URL string still round-trip cleanly.

        Round 21 ``setattr-persists-value-before-validation`` (F-R21-1)
        closure: validators run BEFORE ``super().__setattr__`` so a
        ``ValueError`` leaves the instance unchanged. Pre-fix the legacy
        ``super().__setattr__`` ran unconditionally at the top of this
        method, so a caller that wraps ``setattr(cfg, k, v)`` in
        ``try/except ValueError: pass`` (plugin frameworks, dynamic-
        reload paths, test harnesses) ended up operating on the rejected
        value despite the loud ``ValueError`` -- a contract violation
        relative to the usual write-fails-cleanly invariant. Cross-field
        checks (e.g. pool keepalive ratio) compare the *would-be* value
        against the *current* peer field; since we haven't persisted yet
        the peer read via ``self.<peer>`` is the still-correct prior
        value.

        Round 27 ``ServerConfig-constructor-bypasses-per-field-validators``
        (F-R27-1) closure: per-field validation now lives in the shared
        :meth:`_validate_field` helper so :meth:`__post_init__` can
        re-run it across every ``_VALIDATED_FIELDS`` entry at
        construction time. This method's role is unchanged --
        short-circuit during ``__post_init__``, gate-check the
        validated-field set, then dispatch to ``_validate_field``,
        then persist.
        """
        # Only re-validate after ``__post_init__`` has finished -- the
        # initial dataclass-generated assignments happen before
        # ``__post_init__`` runs the inline validator and would
        # otherwise raise prematurely against a partially-constructed
        # instance. The ``_post_init_done`` flag is set via
        # ``object.__setattr__`` (bypassing this method) at the end of
        # ``__post_init__``.
        if not getattr(self, "_post_init_done", False):
            super().__setattr__(name, value)
            return
        # Round 23 ``_VALIDATED_FIELDS-is-per-instance-dataclass-field``
        # (F-R23-1) closure: look up the gate set via ``type(self)``
        # (NOT ``self``) so an instance-level shadow attribute (which
        # Python allows even on ``ClassVar``-annotated names) cannot
        # bypass the validator. Reading via the class attribute always
        # returns the canonical frozenset, regardless of any
        # ``cfg._VALIDATED_FIELDS = frozenset()`` attempt to neutralize.
        if name not in type(self)._VALIDATED_FIELDS:
            super().__setattr__(name, value)
            return
        # Round 27 F-R27-1 closure: per-field validators now live in
        # ``_validate_field`` so ``__post_init__`` can re-run them on
        # the just-constructed instance. Mutation-path semantics
        # unchanged: validate then persist; on ``ValueError`` the
        # instance state stays at the prior value (R21 F-R21-1).
        self._validate_field(name, value)
        # Round 21 ``setattr-persists-value-before-validation`` (F-R21-1)
        # closure: persist ONLY after the validator above has passed,
        # so a ``ValueError`` leaves the instance unchanged. Callers that
        # catch-and-continue on assignment failure now see the prior
        # value rather than the silently-clamped bad one.
        super().__setattr__(name, value)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ServerConfig:
        """Construct a config populated from environment variables.

        Recognized variables (all prefixed ``SIGNET_``). The list below
        matches the implementation 1:1 -- every variable parsed here is
        documented; nothing is silently swallowed. See the dataclass
        attribute docstrings for the meaning of each field.

        * ``SIGNET_UPSTREAM_URL`` → ``upstream_url`` (str)
        * ``SIGNET_UPSTREAM_API_KEY`` → ``upstream_api_key`` (str)
        * ``SIGNET_UPSTREAM_LABEL`` → ``upstream_label`` (str)
        * ``SIGNET_HOST`` → ``host`` (str)
        * ``SIGNET_PORT`` → ``port`` (int)
        * ``SIGNET_REQUEST_TIMEOUT_S`` → ``request_timeout_s`` (float)
        * ``SIGNET_AUDIT_LOG_PATH`` → ``audit_log_path`` (Path)
        * ``SIGNET_HMAC_KEY_ID`` → ``hmac_key_id`` (str)
        * ``SIGNET_HMAC_SECRET`` → ``hmac_secret`` (hex-encoded bytes;
          e.g. ``openssl rand -hex 32``)
        * ``SIGNET_ALLOW_EPHEMERAL_KEY`` → ``allow_ephemeral_key``
          (bool; see :func:`_parse_bool_env` for accepted spellings)
        * ``SIGNET_RECEIPT_HEADER_NAME`` → ``receipt_header_name`` (str)
        * ``SIGNET_EMIT_RECEIPTS`` → ``emit_receipts`` (bool)
        * ``SIGNET_MAX_REQUEST_BODY_BYTES`` → ``max_request_body_bytes``
          (int)
        * ``SIGNET_STRICT_ERROR_REDACTION`` → ``strict_error_redaction``
          (bool)
        * ``SIGNET_SHADOW`` → ``shadow`` (bool)
        * ``SIGNET_INSPECT_ALL_SSE_LINES`` → ``inspect_all_sse_lines``
          (bool; opt-in to feed non-``data:`` SSE lines into INSPECTION
          per S6)

        CLI-only env vars (NOT parsed here, deliberately):

        * ``SIGNET_LOG_FORMAT`` -- drives JSON-vs-text log formatting at
          process start in ``signet serve``. It configures the root
          logger before a ServerConfig is built, so it is not a
          ``ServerConfig`` field. Read it from your launcher; do not
          expect setting it here to take effect.
        * ``SIGNET_ANONYMIZE_SALT`` -- used by ``signet audit report``
          to salt owner pseudonymization. The audit-report CLI is a
          read-only tool that never instantiates ServerConfig, so this
          var is consumed at the CLI surface, not here.

        Both CLI-only vars are ignored by :meth:`from_env`. Promoting
        either to a ServerConfig field is roadmap (would require
        threading them through to the consuming surfaces); for now,
        document them in the deployment guide rather than silently
        drop them on a ServerConfig-shaped configuration. Variables
        not set fall back to dataclass defaults.

        Raises:
            ValueError: If a value present in ``env`` cannot be parsed
                into the field's type. Errors include the offending env
                var name so misconfigurations are easy to locate (L8).
        """
        e = env if env is not None else dict(os.environ)
        cfg = cls()

        if v := e.get("SIGNET_UPSTREAM_URL"):
            # Round 11 ``from_env-whitespace-and-control-bytes``
            # closure: strip surrounding whitespace so a multi-line
            # YAML / dotenv mis-quote (``SIGNET_UPSTREAM_URL='
            # http://upstream\n'``) is treated as the URL the operator
            # meant rather than silently 502'ing every request. Reject
            # any remaining control byte (< 0x20 or == 0x7f) so a
            # ``\x01`` / ``\x7f`` typo in the env var fails fast at
            # boot rather than 100%-502'ing under httpx's runtime
            # ``InvalidURL`` refusal. Scoped to ``from_env`` (operator
            # input) so direct construction with a CLI-sanitized URL
            # still round-trips through ``ServerConfig(...)`` (see
            # ``__post_init__`` docstring).
            #
            # Round 13 ``from_env-unicode-whitespace-and-bidi``
            # closure: extend the rejection to Unicode whitespace
            # / format-control characters: NBSP (U+00A0), zero-width
            # space (U+200B), zero-width joiner (U+200C-U+200D), bidi
            # marks / overrides (U+200E-U+200F, U+202A-U+202E), and BOM
            # (U+FEFF). Pre-fix any of those embedded mid-URL slipped
            # past the boot guard, urlparse preserved them in the
            # netloc, and httpx / DNS rejected at request time -- the
            # failure mode was then a 502 ``upstream_protocol_violation``
            # that misattributed the root cause. The bidi-override case
            # (U+202E RLO) is a homoglyph-attack vector when the URL is
            # rendered in operator dashboards; rejecting at boot closes
            # that surface too.
            import unicodedata as _ud

            stripped = v.strip()
            for ch in stripped:
                cp = ord(ch)
                if cp < 0x20 or cp == 0x7F:
                    raise ValueError(
                        f"SIGNET_UPSTREAM_URL must not contain control "
                        f"bytes; got codepoint 0x{cp:02x} in "
                        f"SIGNET_UPSTREAM_URL={stripped!r}"
                    )
                # C1 controls (0x80-0x9F).
                if 0x80 <= cp <= 0x9F:
                    raise ValueError(
                        f"SIGNET_UPSTREAM_URL must not contain C1 control "
                        f"bytes; got codepoint 0x{cp:02x} in "
                        f"SIGNET_UPSTREAM_URL={stripped!r}"
                    )
                # Unicode format-control + line/paragraph separators
                # cover NBSP (Zs), ZWSP / BOM / bidi marks / overrides
                # (Cf), and line/para separators (Zl, Zp). Z* covers
                # NBSP (0xA0) which is the most common embedded-Unicode
                # whitespace homoglyph.
                cat = _ud.category(ch)
                if cat in ("Cf", "Zl", "Zp") or cp == 0x00A0:
                    raise ValueError(
                        f"SIGNET_UPSTREAM_URL must not contain Unicode "
                        f"whitespace / format-control characters; got "
                        f"codepoint U+{cp:04X} (category {cat}) in "
                        f"SIGNET_UPSTREAM_URL={stripped!r}"
                    )
            cfg.upstream_url = stripped
        if v := e.get("SIGNET_UPSTREAM_API_KEY"):
            cfg.upstream_api_key = v
        if v := e.get("SIGNET_HOST"):
            cfg.host = v
        if v := e.get("SIGNET_PORT"):
            cfg.port = _parse_int_env("SIGNET_PORT", v)
        if v := e.get("SIGNET_REQUEST_TIMEOUT_S"):
            cfg.request_timeout_s = _parse_float_env("SIGNET_REQUEST_TIMEOUT_S", v)
        if v := e.get("SIGNET_AUDIT_LOG_PATH"):
            cfg.audit_log_path = Path(v)
        if v := e.get("SIGNET_HMAC_KEY_ID"):
            cfg.hmac_key_id = v
        if v := e.get("SIGNET_HMAC_SECRET"):
            cfg.hmac_secret = _parse_hex_env("SIGNET_HMAC_SECRET", v)
        if v := e.get("SIGNET_ALLOW_EPHEMERAL_KEY"):
            cfg.allow_ephemeral_key = _parse_bool_env(v)
        if v := e.get("SIGNET_RECEIPT_HEADER_NAME"):
            cfg.receipt_header_name = v
        if v := e.get("SIGNET_EMIT_RECEIPTS"):
            cfg.emit_receipts = _parse_bool_env(v)
        if v := e.get("SIGNET_MAX_REQUEST_BODY_BYTES"):
            cfg.max_request_body_bytes = _parse_int_env("SIGNET_MAX_REQUEST_BODY_BYTES", v)
        if v := e.get("SIGNET_UPSTREAM_LABEL"):
            cfg.upstream_label = v
        if v := e.get("SIGNET_STRICT_ERROR_REDACTION"):
            cfg.strict_error_redaction = _parse_bool_env(v)
        if v := e.get("SIGNET_SHADOW"):
            cfg.shadow = _parse_bool_env(v)
        if v := e.get("SIGNET_INSPECT_ALL_SSE_LINES"):
            cfg.inspect_all_sse_lines = _parse_bool_env(v)

        # Round 11 ``ServerConfig-mutability-bypasses-scheme-validation``
        # closure: per-field validation now happens in
        # :meth:`__setattr__` on every assignment, so the env-override
        # path is already gated and the legacy explicit
        # ``__post_init__()`` re-run is no longer needed. Left as a
        # no-op-safe call for back-compat with subclassers that may
        # have overridden ``__post_init__`` to add their own checks.
        cfg.__post_init__()
        return cfg
