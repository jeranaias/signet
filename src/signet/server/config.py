"""ServerConfig — runtime configuration for the signet proxy.

A single dataclass that holds every dial the server exposes. Construct
explicitly or via :meth:`from_env` to populate from environment variables
matching the canonical ``SIGNET_*`` namespace.

Attributes are intentionally simple types (str, int, bool, Path) so
configs serialize cleanly to YAML / JSON for declarative deployment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


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
        host: Bind interface for the proxy. Defaults to ``127.0.0.1`` —
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
    and the ``X-Signet-Receipt`` header — incident response correlates
    via the entry ID. Turn off (``--no-strict-error-redaction`` or set
    ``False``) only for development, debugging integration issues, or
    deployments behind a fully-trusted client. ``signet serve --dev``
    flips this off automatically."""

    # Forwarded fields the user can tune via env-var: see _ENV_KEYS below.
    extra_forward_headers: tuple[str, ...] = field(
        default_factory=lambda: ("Authorization", "OpenAI-Beta", "OpenAI-Organization")
    )
    """Headers from the inbound request that are forwarded to the
    upstream verbatim. Owner-resolution and classification headers are
    consumed by signet itself and are NOT forwarded by default."""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ServerConfig:
        """Construct a config populated from environment variables.

        Recognized variables (all prefixed ``SIGNET_``):

        * ``SIGNET_UPSTREAM_URL``
        * ``SIGNET_UPSTREAM_API_KEY``
        * ``SIGNET_HOST``
        * ``SIGNET_PORT``
        * ``SIGNET_REQUEST_TIMEOUT_S``
        * ``SIGNET_AUDIT_LOG_PATH``
        * ``SIGNET_HMAC_KEY_ID``
        * ``SIGNET_HMAC_SECRET`` (hex-encoded; e.g. ``openssl rand -hex 32``)
        * ``SIGNET_ALLOW_EPHEMERAL_KEY`` (``"true"`` / ``"false"``)
        * ``SIGNET_RECEIPT_HEADER_NAME``
        * ``SIGNET_EMIT_RECEIPTS`` (``"true"`` / ``"false"``)

        Variables not set fall back to dataclass defaults.
        """
        e = env if env is not None else dict(os.environ)
        cfg = cls()

        if v := e.get("SIGNET_UPSTREAM_URL"):
            cfg.upstream_url = v
        if v := e.get("SIGNET_UPSTREAM_API_KEY"):
            cfg.upstream_api_key = v
        if v := e.get("SIGNET_HOST"):
            cfg.host = v
        if v := e.get("SIGNET_PORT"):
            cfg.port = int(v)
        if v := e.get("SIGNET_REQUEST_TIMEOUT_S"):
            cfg.request_timeout_s = float(v)
        if v := e.get("SIGNET_AUDIT_LOG_PATH"):
            cfg.audit_log_path = Path(v)
        if v := e.get("SIGNET_HMAC_KEY_ID"):
            cfg.hmac_key_id = v
        if v := e.get("SIGNET_HMAC_SECRET"):
            cfg.hmac_secret = bytes.fromhex(v)
        if v := e.get("SIGNET_ALLOW_EPHEMERAL_KEY"):
            cfg.allow_ephemeral_key = v.lower() == "true"
        if v := e.get("SIGNET_RECEIPT_HEADER_NAME"):
            cfg.receipt_header_name = v
        if v := e.get("SIGNET_EMIT_RECEIPTS"):
            cfg.emit_receipts = v.lower() == "true"
        if v := e.get("SIGNET_MAX_REQUEST_BODY_BYTES"):
            cfg.max_request_body_bytes = int(v)
        if v := e.get("SIGNET_UPSTREAM_LABEL"):
            cfg.upstream_label = v
        if v := e.get("SIGNET_STRICT_ERROR_REDACTION"):
            cfg.strict_error_redaction = v.lower() == "true"

        return cfg
