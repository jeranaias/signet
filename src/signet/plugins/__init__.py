"""Plugin interface — bring-your-own checks via Python entry points.

The 10 built-in checks in :mod:`signet.checks` cover the most common
cases. Anything else — LLM-as-judge, sandbox preview, your own
PII detector, custom session-policy logic — ships as a plugin.

Plugins are discovered via Python's standard ``importlib.metadata``
entry-point mechanism. A plugin package declares an entry under the
``signet.checks`` group:

.. code-block:: toml

    [project.entry-points."signet.checks"]
    tribunal = "my_signet_pkg.tribunal:TribunalCheck"
    sandbox  = "my_signet_pkg.sandbox:SandboxPreviewCheck"

signet then enumerates every entry under that group at startup
(or on demand) and offers them by name to whatever wires up the
:class:`signet.core.pipeline.Pipeline`.

This package provides:

* :func:`signet.plugins.discover` — list every check class registered
  under ``signet.checks``.
* :func:`signet.plugins.load_by_name` — fetch one by entry-point name.
* :class:`signet.plugins.tribunal.TribunalCheck` — reference dual-judge
  dissent check (caller supplies judge endpoint URLs).
* :class:`signet.plugins.sandbox.SandboxPreviewCheck` — reference
  preview-before-commit check (caller supplies sandbox runner).

The two reference plugins illustrate the pattern but are intentionally
minimal — production-tuned implementations live in the proprietary
Pyros engine, not in this OSS release.
"""

from __future__ import annotations

from signet.plugins.discovery import (
    ENTRY_POINT_GROUP,
    discover,
    load_by_name,
    reset_cache,
)
from signet.plugins.sandbox import (
    SandboxPolicy,
    SandboxPreviewCheck,
    SandboxResult,
    SandboxRunner,
)
from signet.plugins.tribunal import TribunalCheck

__all__ = [
    "ENTRY_POINT_GROUP",
    "SandboxPolicy",
    "SandboxPreviewCheck",
    "SandboxResult",
    "SandboxRunner",
    "TribunalCheck",
    "discover",
    "load_by_name",
    "reset_cache",
]
