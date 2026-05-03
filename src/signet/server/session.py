"""Session — cross-request state for multi-turn agents.

A :class:`Session` groups multiple requests under a single shared
context. Useful when the gate's decisions depend on history beyond
the current request — e.g. cumulative token spend across a
conversation, behavioral baselines per session, escalation chains
that span multiple human approvals.

Sessions are caller-driven: the caller asserts a session ID via the
``X-Signet-Session`` header. signet doesn't infer sessions from
heuristics (cookies, owner identity) because that ambiguates
attribution — the caller knows which conversation the request belongs
to; the gate doesn't have to guess.

Storage: :class:`SessionStore` is a protocol; the bundled
:class:`InMemorySessionStore` is the default.

**Production caveats** for the in-memory store:

* **Multi-replica deployments lose sessions on every load-balancer
  flip.** Each replica has an independent dict. Either implement
  :class:`SessionStore` against Redis / Postgres / DynamoDB and pass
  it to :class:`signet.server.app.SignetApp`, or pin sessions to a
  single replica via your LB.
* **No expiration / GC.** Sessions accumulate forever. Long-running
  processes will leak. Implement a periodic sweep over
  ``InMemorySessionStore._sessions`` based on
  :attr:`Session.last_seen_at`, or use an external store with TTLs.
* **No persistence across restarts.** The store is process-local and
  not flushed to disk.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

#: HTTP header carrying the caller-asserted session ID.
HEADER_NAME = "X-Signet-Session"


@dataclass
class Session:
    """One conversation's accumulated state.

    Attributes:
        session_id: Caller-asserted opaque identifier.
        created_at: Wall-clock timestamp of first contact.
        last_seen_at: Wall-clock timestamp of most-recent contact.
        request_count: Number of requests this session has issued.
        scratch: Free-form dict for cross-request state. Checks read
            and write here; signet itself doesn't interpret the
            contents. Common keys (by convention):

            * ``token_budget.cumulative`` — running output-token total
              across the session
            * ``escalation.pending`` — list of escalation decisions
              awaiting human approval
            * ``classification.high_water_mark`` — highest declared
              classification level seen this session
    """

    session_id: str
    created_at: float = field(default_factory=time.time)
    last_seen_at: float = field(default_factory=time.time)
    request_count: int = 0
    scratch: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """Update ``last_seen_at`` and increment ``request_count``."""
        self.last_seen_at = time.time()
        self.request_count += 1


class SessionStore(Protocol):
    """Protocol for storing :class:`Session` objects."""

    def get(self, session_id: str) -> Session | None: ...

    def get_or_create(self, session_id: str) -> Session: ...

    def save(self, session: Session) -> None: ...

    def delete(self, session_id: str) -> None: ...


class InMemorySessionStore:
    """Process-local session store. Fine for single-replica deployments.

    For multi-replica or persistent storage, implement
    :class:`SessionStore` against your backing store of choice.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def get_or_create(self, session_id: str) -> Session:
        existing = self._sessions.get(session_id)
        if existing is not None:
            return existing
        new = Session(session_id=session_id)
        self._sessions[session_id] = new
        return new

    def save(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)


def new_session_id() -> str:
    """Generate a new opaque session identifier.

    Callers normally allocate session IDs themselves; this helper
    exists so signet code (CLI, demos, tests) can mint them when
    needed.
    """
    return str(uuid.uuid4())
