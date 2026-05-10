"""Plugin discovery -- read the standard signet entry-point groups.

The discovery layer is intentionally thin. It enumerates entry points,
loads them on demand, validates them against the ABI contract and the
:class:`signet.core.check.Check` base, and reports the result in a
structured form the CLI can render.

Three entry-point groups are walked:

* ``signet.checks`` -- full :class:`Check` subclasses (the common case;
  ABI-version checked).
* ``signet.adapters`` -- drop-in HTTP adapters.
* ``signet.anchors`` -- external anchor backends.

Caching: results from :func:`discover_plugins` are cached for the
process lifetime, since entry points don't change between Python
interpreter startups. Pass ``refresh=True`` (or call
:func:`reset_cache`) in tests that install plugins mid-run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from signet.core.check import Check

#: Entry-point group name for full Check subclasses. Plugin packages
#: declare under ``[project.entry-points."signet.checks"]`` in
#: ``pyproject.toml``.
ENTRY_POINT_GROUP = "signet.checks"

#: All groups signet walks at startup. Only ``signet.checks`` is ABI-
#: version checked; adapters and anchors have their own contracts.
ENTRY_POINT_GROUPS: tuple[str, ...] = (
    "signet.checks",
    "signet.adapters",
    "signet.anchors",
)

logger = logging.getLogger("signet.plugins")


PluginStatus = Literal[
    "loaded", "incompatible_abi", "load_error", "duplicate_name"
]


@dataclass(frozen=True, slots=True)
class DiscoveredPlugin:
    """One entry point discovered at startup.

    Attributes:
        group: Entry-point group name --
            ``"signet.checks"``, ``"signet.adapters"`` or
            ``"signet.anchors"``.
        name: The entry-point name (the key on the left in
            ``pyproject.toml``).
        package: The distribution that registered the entry point.
            ``""`` if the distribution metadata could not be resolved.
        package_version: The distribution version, or ``""`` when
            unknown.
        target: ``"module.path:Symbol"`` -- the entry point's value.
        status: ``"loaded"`` for a successfully loaded plugin,
            ``"incompatible_abi"`` when the plugin declares an ABI
            version signet does not accept, ``"load_error"`` when
            ``EntryPoint.load()`` raised or the loaded object failed
            type validation, or ``"duplicate_name"`` when two or more
            packages register the same ``(group, name)`` pair (in
            which case ``obj`` is cleared so a silently shadowed class
            cannot be invoked).
        abi_declared: The plugin's declared :data:`CHECK_ABI_VERSION`
            (only meaningful for the ``signet.checks`` group). ``None``
            when the plugin failed to load or did not declare one.
        abi_required: signet's ``CHECK_ABI_VERSION`` at the time of
            discovery.
        error: Populated on ``load_error`` (the exception text),
            ``incompatible_abi`` (a human-readable mismatch message),
            or ``duplicate_name`` (a message naming the conflicting
            packages); ``None`` otherwise.
        obj: The loaded class. Only set when ``status == "loaded"``.
        duplicate_with: When ``status == "duplicate_name"``, the
            distribution names of the OTHER packages that registered
            the same ``(group, name)`` pair. Empty tuple in every
            other status. CLI surfaces (``signet plugins list``,
            ``signet plugins doctor``) read this to render a
            disambiguation hint.
    """

    group: str
    name: str
    package: str
    package_version: str
    target: str
    status: PluginStatus
    abi_declared: int | None
    abi_required: int
    error: str | None
    obj: Any | None
    duplicate_with: tuple[str, ...] = field(default=())


_DISCOVERED_PLUGINS_CACHE: list[DiscoveredPlugin] | None = None
_DISCOVERED_CHECKS_CACHE: dict[str, type[Check]] | None = None


def discover_plugins(*, refresh: bool = False) -> list[DiscoveredPlugin]:
    """Walk the standard plugin entry-point groups and return a
    discovery report.

    Args:
        refresh: If ``True``, ignore any cached discovery and rebuild.

    Returns:
        List of :class:`DiscoveredPlugin` entries -- one per discovered
        entry point across :data:`ENTRY_POINT_GROUPS`. Includes failed
        loads and ABI mismatches so the CLI can surface misconfiguration
        instead of dropping it on the floor.

    Cached after first call; pass ``refresh=True`` to re-scan (useful
    in tests and for the future hot-reload feature).

    .. note::
        Identity stability: consecutive calls with ``refresh=False``
        return the SAME list object (Python ``is`` comparison succeeds).
        A call with ``refresh=True`` rebuilds the cache and returns a
        NEW list object, so callers that captured a reference from a
        prior call will continue to see the stale snapshot. Do not rely
        on identity for change-detection -- compare the contents
        explicitly, or call :func:`reset_cache` and re-fetch.
    """
    global _DISCOVERED_PLUGINS_CACHE, _DISCOVERED_CHECKS_CACHE
    if _DISCOVERED_PLUGINS_CACHE is not None and not refresh:
        return _DISCOVERED_PLUGINS_CACHE

    from signet.core.check import CHECK_ABI_VERSION, Check

    results: list[DiscoveredPlugin] = []
    checks: dict[str, type[Check]] = {}

    for group in ENTRY_POINT_GROUPS:
        for ep in _iter_entry_points(group):
            pkg, ver = _ep_distribution(ep)
            common = {
                "group": group,
                "name": ep.name,
                "package": pkg,
                "package_version": ver,
                "target": ep.value,
                "abi_required": CHECK_ABI_VERSION,
            }

            try:
                obj = ep.load()
            except Exception as exc:
                logger.warning(
                    "signet plugin %r (%s) failed to load: %s: %s",
                    ep.name,
                    group,
                    type(exc).__name__,
                    exc,
                )
                results.append(
                    DiscoveredPlugin(
                        **common,
                        status="load_error",
                        abi_declared=None,
                        error=f"{type(exc).__name__}: {exc}",
                        obj=None,
                    )
                )
                continue

            if group == "signet.checks":
                if not (isinstance(obj, type) and issubclass(obj, Check)):
                    msg = (
                        f"resolved object {obj!r} is not a Check subclass"
                    )
                    logger.warning(
                        "signet plugin %r resolved to %r which is not a Check subclass; skipping",
                        ep.name,
                        obj,
                    )
                    results.append(
                        DiscoveredPlugin(
                            **common,
                            status="load_error",
                            abi_declared=None,
                            error=msg,
                            obj=None,
                        )
                    )
                    continue

                declared = getattr(obj, "CHECK_ABI_VERSION", None)
                if not isinstance(declared, int):
                    msg = (
                        f"plugin class {obj.__name__} did not declare an integer "
                        f"CHECK_ABI_VERSION (got {declared!r})"
                    )
                    logger.warning("%s; skipping", msg)
                    results.append(
                        DiscoveredPlugin(
                            **common,
                            status="incompatible_abi",
                            abi_declared=None,
                            error=msg,
                            obj=None,
                        )
                    )
                    continue

                if declared != CHECK_ABI_VERSION:
                    msg = (
                        f"plugin {ep.name!r} declares CHECK_ABI_VERSION={declared}; "
                        f"signet requires {CHECK_ABI_VERSION}"
                    )
                    logger.warning("%s; refusing to load", msg)
                    results.append(
                        DiscoveredPlugin(
                            **common,
                            status="incompatible_abi",
                            abi_declared=declared,
                            error=msg,
                            obj=None,
                        )
                    )
                    continue

                results.append(
                    DiscoveredPlugin(
                        **common,
                        status="loaded",
                        abi_declared=declared,
                        error=None,
                        obj=obj,
                    )
                )
                checks[ep.name] = obj
            else:
                # adapters / anchors: no ABI gate yet, just record it
                results.append(
                    DiscoveredPlugin(
                        **common,
                        status="loaded",
                        abi_declared=None,
                        error=None,
                        obj=obj,
                    )
                )

    # Detect duplicate (group, name) registrations. importlib.metadata
    # happily returns multiple entry points with the same name when two
    # packages both register one -- the first by install order wins
    # silently. Plugin upgrades that retain the name but change the
    # import path therefore appear successful while still running the
    # old class. We refuse the ambiguity at discovery time and let the
    # CLI surface it.
    seen_keys: dict[tuple[str, str], list[int]] = {}
    for idx, plugin in enumerate(results):
        seen_keys.setdefault((plugin.group, plugin.name), []).append(idx)

    for (_group, _name), indices in seen_keys.items():
        if len(indices) <= 1:
            continue
        # Build a stable list of the conflicting packages, with a
        # placeholder for entry points whose distribution metadata
        # could not be resolved (so the message is still actionable).
        package_labels = [
            results[i].package or "<unknown distribution>" for i in indices
        ]
        for idx in indices:
            others = tuple(
                package_labels[j] for j, other_idx in enumerate(indices)
                if other_idx != idx
            )
            this_pkg = results[idx].package or "<unknown distribution>"
            msg = (
                f"entry-point name {results[idx].name!r} in group "
                f"{results[idx].group!r} is also registered by: "
                f"{', '.join(others)} (this entry: {this_pkg})"
            )
            logger.warning("%s; refusing to load (ambiguous)", msg)
            results[idx] = replace(
                results[idx],
                status="duplicate_name",
                error=msg,
                obj=None,
                duplicate_with=others,
            )
        # If any collisions land on signet.checks, drop the now-unsafe
        # entries from the back-compat checks map so discover() doesn't
        # hand callers a shadowed class.
        if results[indices[0]].group == "signet.checks":
            checks.pop(results[indices[0]].name, None)

    _DISCOVERED_PLUGINS_CACHE = results
    _DISCOVERED_CHECKS_CACHE = checks
    return results


def discover(*, refresh: bool = False) -> dict[str, type[Check]]:
    """Enumerate every check class registered under ``signet.checks``.

    Backwards-compatible facade over :func:`discover_plugins`. Only
    successfully loaded ``signet.checks`` entries are returned; load
    errors and ABI mismatches are still recorded in
    :func:`discover_plugins` and visible to the CLI.

    Args:
        refresh: If ``True``, ignore any cached discovery and rebuild.

    Returns:
        Dict mapping entry-point names to Check subclasses.
    """
    discover_plugins(refresh=refresh)
    assert _DISCOVERED_CHECKS_CACHE is not None  # populated by discover_plugins
    return dict(_DISCOVERED_CHECKS_CACHE)


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
    global _DISCOVERED_PLUGINS_CACHE, _DISCOVERED_CHECKS_CACHE
    _DISCOVERED_PLUGINS_CACHE = None
    _DISCOVERED_CHECKS_CACHE = None


def _iter_entry_points(group: str) -> list[EntryPoint]:
    """Return every entry point registered under ``group``.

    Uses the ``entry_points().select(group=...)`` API standardized in
    Python 3.10. signet pins ``requires-python >= 3.11`` so older
    ``EntryPoints`` dict-shaped fallbacks are unnecessary.
    """
    return list(entry_points().select(group=group))


def _ep_distribution(ep: EntryPoint) -> tuple[str, str]:
    """Best-effort resolve ``(distribution_name, version)`` for an
    entry point. Returns ``("", "")`` when the metadata link is
    unavailable (e.g. dynamically-registered entry points in tests).
    """
    dist = getattr(ep, "dist", None)
    if dist is None:
        return ("", "")
    name = getattr(dist, "name", "") or ""
    version = getattr(dist, "version", "") or ""
    return (name, version)


__all__ = [
    "ENTRY_POINT_GROUP",
    "ENTRY_POINT_GROUPS",
    "DiscoveredPlugin",
    "PluginStatus",
    "discover",
    "discover_plugins",
    "load_by_name",
    "reset_cache",
]
