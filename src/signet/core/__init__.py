"""Core abstractions: the building blocks the rest of signet composes.

Nothing here knows about HTTP, OpenAI, or any specific upstream. Adapters live
in :mod:`signet.adapters` and :mod:`signet.server`. Concrete checks live in
:mod:`signet.checks`.

The four primitives:

* :class:`Owner` -- who is accountable for a request
* :class:`AuditEntry` -- a single immutable decision record
* :class:`Check` -- a single policy evaluation step
* :class:`Pipeline` -- sequenced execution of checks against a request
"""

from __future__ import annotations

__all__: list[str] = []
