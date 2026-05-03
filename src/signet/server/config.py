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

        return cfg
