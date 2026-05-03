"""Anthropic SDK adapter — wrap an anthropic client to route through signet.

Usage::

    from anthropic import Anthropic
    from signet.adapters.anthropic import wrap_anthropic

    client = wrap_anthropic(
        Anthropic(api_key="sk-ant-..."),
        signet_url="http://localhost:8443/v1",
        owner="human:alice@example.com",
    )

Note: signet's proxy speaks the OpenAI chat-completions wire format.
This adapter is for the case where you're calling an Anthropic model
*through* an upstream that translates (LiteLLM, an OpenAI-compatible
Anthropic gateway, or your own translation layer). signet itself does
not translate between OpenAI and Anthropic message formats — set the
upstream URL to a translator if you need that.

If you're calling Anthropic's native Messages API directly, you have
two options:

1. Run signet as an OpenAI-compatible front-end to a translator
   (recommended; this adapter handles the SDK side).
2. Call Anthropic without signet for the request itself, but use
   signet's pipeline programmatically to evaluate decisions
   (see :doc:`docs/embed`).
"""

from __future__ import annotations

from typing import TypeVar

ClientT = TypeVar("ClientT")


def wrap_anthropic(
    client: ClientT,
    *,
    signet_url: str,
    owner: str | None = None,
    agent_id: str | None = None,
    policy: str | None = None,
    classification: str | None = None,
    clearance: str | None = None,
    session_id: str | None = None,
) -> ClientT:
    """Reconfigure an Anthropic SDK client to route through signet.

    Same shape and constraints as
    :func:`signet.adapters.openai.wrap_openai`. See that function's
    docstring for argument details.

    Returns the same client instance after in-place reconfiguration.
    """
    if not any((owner, agent_id, policy)):
        raise ValueError(
            "wrap_anthropic requires one of `owner`, `agent_id`, or `policy` "
            "(signet refuses requests without a resolvable commit owner)"
        )

    headers: dict[str, str] = {}
    if owner:
        headers["X-Commit-Owner"] = owner
    if agent_id:
        headers["X-Agent-Id"] = agent_id
    if policy:
        headers["X-Policy-Name"] = policy
    if classification:
        headers["X-Classification"] = classification
    if clearance:
        headers["X-Caller-Clearance"] = clearance
    if session_id:
        headers["X-Signet-Session"] = session_id

    # Anthropic SDK exposes base_url and default_headers on the client.
    client.base_url = signet_url
    if hasattr(client, "default_headers"):
        existing = dict(client.default_headers or {})
        existing.update(headers)
        client.default_headers = existing
    else:
        client._signet_headers = headers
    return client


__all__ = ["wrap_anthropic"]
