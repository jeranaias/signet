"""HTTP proxy server -- the runnable face of signet.

Run via the CLI (``signet serve --upstream <url>``) or import the
:class:`signet.server.app.SignetApp` directly when embedding signet in
another ASGI application.

What this package provides:

* :class:`signet.server.app.SignetApp` -- the FastAPI application.
* :class:`signet.server.config.ServerConfig` -- runtime configuration.
* :class:`signet.server.session.Session` + :class:`SessionStore` --
  cross-request state for multi-turn agents.
* :class:`signet.server.receipt.ReceiptSigner` + helpers -- produces
  ``X-Signet-Receipt`` HMAC-signed decision summaries that callers can
  verify offline.

The proxy is OpenAI chat-completions-compatible. Callers point any
OpenAI SDK at signet's ``/v1/chat/completions`` endpoint, signet runs
the configured pipeline, and (if checks pass) forwards to the
configured upstream URL -- vLLM, OpenAI, Anthropic, Ollama, anything
that speaks OpenAI's wire format.
"""

from __future__ import annotations

from signet.server.app import SignetApp
from signet.server.config import ServerConfig
from signet.server.receipt import (
    ALG_ED25519,
    ALG_HMAC_SHA256,
    DEFAULT_HEADER_NAME,
    Ed25519ReceiptSigner,
    HmacReceiptSigner,
    ReceiptSigner,
    parse_header,
)
from signet.server.session import (
    HEADER_NAME as SESSION_HEADER_NAME,
)
from signet.server.session import (
    InMemorySessionStore,
    Session,
    SessionStore,
    new_session_id,
)

__all__ = [
    "ALG_ED25519",
    "ALG_HMAC_SHA256",
    "DEFAULT_HEADER_NAME",
    "SESSION_HEADER_NAME",
    "Ed25519ReceiptSigner",
    "HmacReceiptSigner",
    "InMemorySessionStore",
    "ReceiptSigner",
    "ServerConfig",
    "Session",
    "SessionStore",
    "SignetApp",
    "new_session_id",
    "parse_header",
]
