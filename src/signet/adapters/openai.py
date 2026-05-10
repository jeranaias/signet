"""OpenAI SDK adapter -- wrap an openai client to route through signet.

Usage::

    from openai import OpenAI
    from signet.adapters.openai import wrap_openai

    client = wrap_openai(
        OpenAI(api_key="sk-..."),                 # the underlying SDK client
        signet_url="http://localhost:8443/v1",    # the signet proxy
        owner="human:alice@example.com",          # required by signet
    )

    # Use the client exactly as you would the underlying SDK:
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )

The wrapper rewrites ``base_url`` and adds default headers so every
subsequent call carries the signet-required attribution headers. The
underlying SDK is otherwise untouched -- no patching, no monkey-business.

The :func:`wrap_openai` function works on both ``openai.OpenAI``
(sync) and ``openai.AsyncOpenAI`` (async) clients.
"""

from __future__ import annotations

import warnings
from typing import TypeVar

ClientT = TypeVar("ClientT")

#: Owner-attribution prefixes signet recognizes as well-formed (L2).
#: A value lacking any of these is accepted (we don't reject bad
#: owners -- the audit chain still records exactly what the caller
#: provided), but a ``UserWarning`` fires so the misuse is visible
#: in test runs and dev consoles. Keep this in sync with the
#: ``Owner`` model in :mod:`signet.core.owner`.
_KNOWN_OWNER_PREFIXES: tuple[str, ...] = ("human:", "agent:", "policy:")


def _warn_if_unprefixed_owner(owner: str | None, *, adapter_name: str) -> None:
    """Emit a UserWarning when ``owner`` lacks a known attribution prefix.

    Soft validation only: the audit chain still records whatever the
    caller passed, so misuse is recoverable post-hoc. The warning
    surfaces the misuse at wrap-time so dev consoles and CI test runs
    catch it before production traffic flows.
    """
    if owner and not any(owner.startswith(p) for p in _KNOWN_OWNER_PREFIXES):
        warnings.warn(
            f"owner={owner!r} does not start with a known prefix "
            f"(expected one of: {_KNOWN_OWNER_PREFIXES}). signet will treat "
            "it as a literal string but the audit chain will record an "
            "unattributed owner shape. Suggested form: 'human:<email>' or "
            f"'agent:<id>'. ({adapter_name})",
            UserWarning,
            stacklevel=3,
        )


def wrap_openai(
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
    """Reconfigure an OpenAI SDK client to route through signet.

    Args:
        client: An ``openai.OpenAI`` or ``openai.AsyncOpenAI`` instance.
        signet_url: Base URL of the signet proxy (e.g.
            ``"http://localhost:8443/v1"``).
        owner: Value for ``X-Commit-Owner``. Conventionally
            ``"human:<principal>"``. Mutually exclusive with
            ``agent_id`` and ``policy``.
        agent_id: Value for ``X-Agent-Id``. Use for autonomous agents.
        policy: Value for ``X-Policy-Name``. Use when an
            organizational policy delegates authority.
        classification: Optional ``X-Classification`` header value
            (e.g. ``"SECRET"``).
        clearance: Optional ``X-Caller-Clearance`` header value
            (e.g. ``"TS"``).
        session_id: Optional ``X-Signet-Session`` value to associate
            this client's requests with a multi-turn session.

    Returns:
        The same client instance, with ``base_url`` set to the signet
        proxy and default headers populated. Returned for ergonomic
        ``client = wrap_openai(OpenAI())`` chaining; the wrap is
        in-place.

    Raises:
        ValueError: If none of ``owner``, ``agent_id``, ``policy`` is
            provided. signet always requires a resolvable owner.
    """
    if not any((owner, agent_id, policy)):
        raise ValueError(
            "wrap_openai requires one of `owner`, `agent_id`, or `policy` "
            "(signet refuses requests without a resolvable commit owner)"
        )

    _warn_if_unprefixed_owner(owner, adapter_name="wrap_openai")

    # Tested against openai>=1.0. The SDK exposes ``base_url`` and
    # ``default_headers`` as mutable attributes; if a future major
    # rewrite removes either, fail loudly here rather than silently
    # produce a client that bypasses the proxy.
    if not hasattr(client, "base_url"):
        raise TypeError(
            f"wrap_openai expected an OpenAI SDK client with a writable "
            f"`base_url` attribute; got {type(client).__name__!r}. "
            "Confirm openai>=1.0 is installed."
        )

    headers = _build_headers(
        owner=owner,
        agent_id=agent_id,
        policy=policy,
        classification=classification,
        clearance=clearance,
        session_id=session_id,
    )

    client.base_url = signet_url
    if hasattr(client, "default_headers"):
        existing = dict(client.default_headers or {})
        existing.update(headers)
        client.default_headers = existing
    else:
        # Older SDK versions: stash on a custom attribute the user can
        # supply manually. Document this in the migration notes.
        client._signet_headers = headers  # type: ignore[attr-defined]
    return client


def _build_headers(
    *,
    owner: str | None,
    agent_id: str | None,
    policy: str | None,
    classification: str | None,
    clearance: str | None,
    session_id: str | None,
) -> dict[str, str]:
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
    return headers


__all__ = ["wrap_openai"]
