"""Plugin discovery — read the ``signet.checks`` entry-point group.

The discovery layer is intentionally thin. It enumerates entry points,
loads them on demand, and validates that the loaded object is a
:class:`signet.core.check.Check` subclass. Nothing else.

Caching: results from :func:`discover` are cached for the process
lifetime, since entry points don't change between Python interpreter
startups. Call :func:`reset_cache` in tests that install plugins
mid-run.
"""

from __future__ import annotations

import logging
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from signet.core.check import Check

#: Entry-point group name. Plugin packages declare under
#: ``[project.entry-points."signet.checks"]`` in pyproject.toml.
ENTRY_POINT_GROUP = "signet.checks"

logger = logging.getLogger("signet.plugins")

_DISCOVERED_CACHE: dict[str, type[Check]] | None = None


def discover(*, refresh: bool = False) -> dict[str, type[Check]]:
    """Enumerate every check class registered under ``signet.checks``.

    Args:
        refresh: If ``True``, ignore any cached discovery and rebuild.

    Returns:
        Dict mapping entry-point names to Check subclasses. Names with
        loading errors are skipped and logged at WARNING.
    """
    global _DISCOVERED_CACHE
    if _DISCOVERED_CACHE is not None and not refresh:
        return _DISCOVERED_CACHE

    from signet.core.check import Check

    found: dict[str, type[Check]] = {}
    for ep in _iter_entry_points():
        try:
            obj = ep.load()
        except Exception as exc:
            logger.warning(
                "signet plugin %r failed to load: %s: %s",
                ep.name,
                type(exc).__name__,
                exc,
            )
            continue
        if not (isinstance(obj, type) and issubclass(obj, Check)):
            logger.warning(
                "signet plugin %r resolved to %r which is not a Check subclass; skipping",
                ep.name,
                obj,
            )
            continue
        found[ep.name] = obj

    _DISCOVERED_CACHE = found
    return found


def load_by_name(name: str) -> type[Check]:
    """Load one plugin by its entry-point name.

    Raises:
        KeyError: When no plugin with that name is registered.
    """
    plugins = discover()
    try:
        return plugins[name]
    except KeyError as exc:
        known = sorted(plugins) or ["(none registered)"]
        raise KeyError(
            f"no signet plugin named {name!r}; known plugins: {', '.join(known)}"
        ) from exc


def reset_cache() -> None:
    """Drop the discovery cache. Useful in tests that register plugins
    after first import."""
    global _DISCOVERED_CACHE
    _DISCOVERED_CACHE = None


def _iter_entry_points() -> list[EntryPoint]:
    """Compatibility shim for entry_points() shape across Python versions.

    importlib.metadata returns a ``SelectableGroups``-shaped object on
    Python 3.10+ and a ``dict``-shaped object on older versions.
    """
    eps = entry_points()
    select = getattr(eps, "select", None)
    if callable(select):
        return list(select(group=ENTRY_POINT_GROUP))
    # Fallback for very old shapes
    return list(eps.get(ENTRY_POINT_GROUP, []))


__all__ = ["ENTRY_POINT_GROUP", "discover", "load_by_name", "reset_cache"]
