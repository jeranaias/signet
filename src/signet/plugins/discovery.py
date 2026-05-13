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
from typing import TYPE_CHECKING, Any, Literal, cast

# Round 9 MED: ASCII control-byte translation table mirrored from
# ``signet.cli._sanitize_for_terminal``. Plugin metadata (entry-point
# name, distribution name, exception text) flows through stdlib
# logging here and the default handler writes to stderr, which a
# terminal renders directly. A hostile plugin can therefore inject
# ANSI / OSC bytes through the WARNING-level discovery log lines.
# We sanitize at the log-site so the defense is local to the module
# that produces the untrusted strings -- no cross-module import.
#
# Round 14 INFO: extended to also escape Unicode classes that pass
# through ASCII-only sanitization but still render in modern terminals
# -- C1 controls, bidi overrides / isolates (Trojan Source), line and
# paragraph separators, and BOM. Mirrors the same table in
# ``signet.cli`` and ``signet.bench``. See cli.py for the full rationale.
_CONTROL_BYTE_REPLACEMENTS: dict[int, str] = {b: f"\\x{b:02x}" for b in range(0x20)}
_CONTROL_BYTE_REPLACEMENTS[0x7F] = "\\x7f"
_CONTROL_BYTE_REPLACEMENTS.pop(0x09, None)  # preserve TAB
_UNICODE_CONTROL_CODEPOINTS: tuple[int, ...] = (
    *range(0x80, 0xA0),  # C1 controls
    *range(0x202A, 0x202F),  # bidi overrides
    *range(0x2066, 0x206A),  # bidi isolates
    0x2028,  # LINE SEPARATOR
    0x2029,  # PARAGRAPH SEPARATOR
    0xFEFF,  # ZWNBSP / BOM
)
for _cp in _UNICODE_CONTROL_CODEPOINTS:
    _CONTROL_BYTE_REPLACEMENTS[_cp] = f"\\u{_cp:04x}"
del _cp


def _sanitize_for_log(value: object) -> str:
    """Render *value* as a terminal-safe string for log emission.

    Round 14 INFO: also escapes Unicode bidi overrides / isolates, C1
    controls, line / paragraph separators, and BOM in addition to ASCII
    control bytes. Hostile ``__repr__`` output from a plugin can be
    rendered through this helper (via ``_sanitize_for_log(repr(obj))``)
    to neutralize Trojan Source and 8-bit CSI vectors before stdlib
    logging writes to stderr.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.translate(_CONTROL_BYTE_REPLACEMENTS)


# Round 15 LOW (F-R15-2): cap the length of plugin-controlled strings
# (typically ``repr()`` output of a plugin object) before sanitization.
# A hostile plugin whose ``__repr__`` returns 10 MB of bytes makes
# ``_sanitize_for_log(repr(obj))`` allocate ~15 MB of escaped output and
# stalls discovery ~9.5 s. Discovery is operator-triggered and runs
# inside the trust boundary, so this is UX (slow-start ``signet serve``,
# wedged ``plugins doctor``) rather than a data-exposure vector --
# but the cap is cheap and predictable. We truncate at 1024 chars
# (more than enough to identify the offending object) and append a
# ``... [truncated]`` marker that the sanitizer leaves intact.
_LOG_TRUNCATION_MARKER = "... [truncated]"


def _truncate_for_log(s: str, max_chars: int = 1024) -> str:
    """Truncate *s* to at most *max_chars* characters.

    Pre-cap helper for the ``_sanitize_for_log(repr(obj))`` pattern --
    smaller input means a faster sanitize and a bounded log line. If
    truncation happens, an explicit ``... [truncated]`` marker is
    appended so an operator reading the log can see the cut without
    going hunting for the missing tail. Non-string inputs are coerced
    via ``str()`` first so callers can pass arbitrary metadata values.

    .. important::
        Every callsite that interpolates a plugin-controlled string
        through ``_sanitize_for_log`` MUST wrap the input in
        ``_truncate_for_log`` first. A plugin's ``__repr__`` /
        ``__str__`` / exception ``__str__`` can return arbitrary
        megabyte-scale bytes, and the per-codepoint translation in
        ``_sanitize_for_log`` is O(n) in the input length. Without the
        cap, a hostile plugin can stall discovery for tens of seconds
        and cache the multi-MB rendered string in
        ``_DISCOVERED_PLUGINS_CACHE`` for the process lifetime. The
        cap engaged at the load-error branch (F-R17-2), the non-Check
        resolved-object branch (F-R15-2), and the non-integer
        CHECK_ABI_VERSION branch (F-R15-2).
    """
    if not isinstance(s, str):
        s = str(s) if s is not None else ""
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + _LOG_TRUNCATION_MARKER


# Round 21 HIGH (F-R21-1): the R19 ``_safe_repr`` / ``_safe_str``
# fallback path interpolated ``type(exc).__name__`` to record a
# breadcrumb -- but ``type(exc).__name__`` is itself attacker-
# controlled. A hostile plugin can build its exception class via a
# metaclass whose ``__getattribute__`` raises on ``name == '__name__'``,
# which propagates a FRESH exception out of the helper's own ``except``
# branch, defeating exactly the R19 closure. ``_safe_name`` wraps the
# ``__name__`` access in its own ``BaseException`` catch with a
# constant-string fallback so the helper is bulletproof even against a
# hostile metaclass that raises on ``__name__``.
#
# Two access patterns are covered by the SAME helper:
#
# * Exception instance ``exc`` -> caller passes ``type(exc)`` so the
#   helper reads ``type(exc).__name__`` (the class name of the
#   exception). This is the F-R21-1 / F-R21-2 fallback breadcrumb shape.
# * Class object ``cls`` -> caller passes ``cls`` directly so the helper
#   reads ``cls.__name__`` (the class's own name). This is the F-R21-2
#   ``obj.__name__`` shape at the non-integer-ABI branch.
#
# Either way the access is ``<obj>.__name__`` with the same ``BaseException``
# guard, so a single helper is sufficient. Even if ``type(obj)`` itself
# raises (very hostile metaclass), the function still returns ``fallback``
# because the ``BaseException`` catch is wide.
def _safe_name(obj: object, *, fallback: str = "<class repr raised>") -> str:
    """Best-effort ``__name__`` access that never propagates exceptions.

    Returns *fallback* when reading ``obj.__name__`` raises any
    ``BaseException`` subclass -- including the very hostile case of a
    metaclass whose ``__getattribute__`` raises on ``__name__`` access
    (which side-steps a naive ``type(exc).__name__`` interpolation
    inside an ``except`` branch).

    Callers wanting the class name of an exception instance should
    pass ``type(exc)``; callers with a class object in hand pass the
    class directly.

    Round 23 HIGH (F-R23-1): R21 hardened the ``raise`` path, but a
    hostile metaclass ``__getattribute__`` that **returns** an arbitrary
    object instead of a string still made the helper output unsafe.
    Downstream consumers stringify lazily inside ``logging`` and
    f-strings -- if the returned object's ``__str__`` raises, the
    discovery walk aborts on the next interpolation. The helper now
    coerces the result to a real ``str`` (catching any ``BaseException``
    from ``__str__``) and caps it at 256 characters so a hostile
    metaclass that returns a 50 MB string cannot pin the result in
    ``DiscoveredPlugin.error`` for the process lifetime. The output of
    ``_safe_name`` is guaranteed safe to interpolate into f-strings,
    safe to pass to logging, and bounded in length.
    """
    try:
        # Prefer ``obj.__name__`` directly so passing a class returns
        # the class's own name. For instances, callers pass ``type(x)``.
        raw = obj.__name__  # type: ignore[attr-defined]
    except BaseException:
        # Intentional ``BaseException`` catch: a hostile metaclass can
        # override ``__getattribute__`` to raise any ``BaseException``
        # subclass on ``__name__`` access. The point of this helper is
        # to neutralize that vector even from inside another helper's
        # except branch. Also catches the rarer case where ``obj`` has
        # no ``__name__`` attribute at all (AttributeError).
        try:
            # One more belt-and-suspenders: try ``type(obj).__name__``
            # so passing an instance still yields a useful breadcrumb
            # without the caller wrapping in ``type()``. Wrapped in its
            # own ``BaseException`` catch so a very hostile metaclass
            # (one that raises on ``type(obj)`` itself, or on
            # ``__name__`` of the metaclass) still returns *fallback*.
            raw = type(obj).__name__
        except BaseException:
            return fallback
    # Round 23 HIGH (F-R23-1): coerce to a real ``str``. A hostile
    # metaclass ``__getattribute__`` can return an object whose
    # ``__str__`` raises; catch that here so callers never see a
    # surprise raise from an innocent-looking f-string interpolation
    # or ``logger.warning("%s", ...)`` call.
    try:
        if not isinstance(raw, str):
            raw = str(raw)
    except BaseException:
        return fallback
    # Round 27 P0: even when ``isinstance(raw, str)`` returned ``True``,
    # ``raw`` may be a ``str``-SUBCLASS instance whose ``__len__`` /
    # ``__bool__`` / ``__hash__`` / ``__str__`` is overridden to raise.
    # The R23 coerce above is skipped on the subclass branch (the
    # ``isinstance`` gate accepts subclasses), leaking the subclass into
    # the ``len(raw) > 256`` check below, which then invokes the hostile
    # ``__len__`` and aborts the whole discovery walk. Same root family
    # as R26's ``_safe_str_attr`` closure: pass through ``str.__str__``
    # (the unbound plain-``str`` dunder) to return the underlying
    # primitive without ever invoking the subclass override.
    try:
        raw = str.__str__(raw)
    except BaseException:
        return fallback
    # Round 23 MED (F-R23-4): cap the length so a metaclass returning
    # a 50 MB ``__name__`` does not bypass the per-callsite
    # ``_truncate_for_log`` cap. 256 chars is far more than any real
    # class name and keeps the cached ``DiscoveredPlugin.error`` bounded.
    if len(raw) > 256:
        raw = raw[:256] + _LOG_TRUNCATION_MARKER
    return raw


# Round 23 HIGH (F-R23-2): every ``getattr`` on a plugin-controlled
# class is a ``BaseException`` raise primitive -- a hostile metaclass
# ``__getattribute__`` can raise any ``BaseException`` subclass on any
# attribute name. The stdlib ``getattr(obj, name, default)`` only
# swallows ``AttributeError``; everything else escapes and aborts the
# discovery walk. ``_safe_getattr`` widens the catch to ``BaseException``
# so attribute access through plugin-controlled descriptors can never
# crash a callsite, no matter how hostile the metaclass.
def _safe_getattr(obj: object, name: str, default: object = None) -> object:
    """Best-effort ``getattr`` that never propagates exceptions.

    Returns *default* on any ``BaseException`` subclass raised by a
    hostile metaclass ``__getattribute__`` or property descriptor. The
    callers in this module either use the returned value in an
    ``isinstance`` gate (which routes the failure to a structured
    ``load_error`` / ``incompatible_abi`` row downstream) or default-
    coerce it via ``or ""`` for distribution metadata.
    """
    try:
        return getattr(obj, name, default)
    except BaseException:
        # Intentional ``BaseException`` catch: same rationale as
        # ``_safe_name`` -- the point of this helper is to neutralize
        # the hostile-attribute-access vector even from deep inside
        # the discovery walk.
        return default


# Round 23 HIGH (F-R23-3): ``isinstance(obj, cls)`` reads
# ``obj.__class__`` via the standard descriptor protocol. A plugin
# whose resolved object overrides ``__class__`` as a ``@property``
# that raises crashes the ``isinstance`` call itself, escaping the
# surrounding ``try`` (which only wraps ``ep.load()``). The wrapper
# returns *fallback* on any ``BaseException`` so the gate can route
# the failure into a structured ``load_error`` row.
def _safe_isinstance(obj: object, cls: type | tuple[type, ...], *, fallback: bool = False) -> bool:
    """Best-effort ``isinstance`` that never propagates exceptions."""
    try:
        return isinstance(obj, cls)
    except BaseException:
        return fallback


def _safe_issubclass(obj: object, cls: type | tuple[type, ...], *, fallback: bool = False) -> bool:
    """Best-effort ``issubclass`` that never propagates exceptions.

    Same shape as :func:`_safe_isinstance` but for the subclass gate.
    A plugin's metaclass can override ``__subclasscheck__`` to raise.
    """
    try:
        return issubclass(obj, cls)  # type: ignore[arg-type]
    except BaseException:
        return fallback


# Round 25 HIGH (F-R25-1/2/3/4/5/6/7): every direct attribute read on a
# plugin-controlled ``EntryPoint`` or ``Distribution`` (``ep.name``,
# ``ep.value``, ``dist.name``, ``dist.version``) is the SAME
# ``BaseException`` raise primitive ``_safe_getattr`` already neutralizes
# for arbitrary attribute names -- but with an additional twist the R23
# helpers don't address: a hostile ``EntryPoint`` subclass can return a
# ``str``-SUBCLASS instance whose ``__bool__`` / ``__len__`` / ``__hash__``
# / ``__str__`` is overridden to raise. The R24 ``isinstance(..., str)``
# gates accept the subclass (an ``__instancecheck__`` win for the plugin)
# but every downstream consumer (``or "x"``, ``len(v)``, ``dict[k] = ...``,
# ``f"{v}"``) invokes one of those dunders lazily and crashes the walk.
#
# ``_safe_str_attr`` combines ``_safe_getattr`` (catches the raise) with
# ``str.__str__(value)`` (the unbound-method form bypasses any subclass
# ``__str__`` override and returns the raw underlying plain-``str``).
# The output is guaranteed to be a plain ``str`` instance: hashable,
# bool-able, len-able, format-able without ever invoking a hostile
# subclass dunder. Apply at every read of an ``EntryPoint`` /
# ``Distribution`` string-typed attribute.
def _safe_str_attr(obj: object, name: str, *, default: str = "") -> str:
    """Best-effort plain-``str`` attribute read on a plugin-controlled value.

    Robust against three independent hostile shapes:

    1. ``@property``/``__getattribute__`` raising on the attribute access
       (``BaseException`` catch via :func:`_safe_getattr`).
    2. A non-string returned value (coerced via the safe ``str()``
       fallback used by :func:`_safe_str`).
    3. A ``str``-subclass instance whose ``__bool__``/``__len__``/
       ``__hash__``/``__str__`` is overridden to raise -- ``isinstance(
       v, str)`` returns ``True`` but downstream consumers crash on the
       lazy dunder invocation. Mitigated by ``str.__str__(v)`` which
       invokes the plain-``str`` dunder, returning the underlying
       primitive without touching the subclass override.

    Always returns a plain ``str`` (never a subclass).
    """
    try:
        value = getattr(obj, name, default)
    except BaseException:
        return default
    if isinstance(value, str):
        # str-subclass safety: ``str.__str__`` is the unbound dunder.
        # Calling it explicitly returns the underlying plain-str without
        # invoking the subclass ``__str__`` (which might raise). A
        # hostile str-subclass cannot escape this coerce.
        try:
            return str.__str__(value)
        except BaseException:
            return default
    # Non-string returned value -- fall through to the existing
    # ``_safe_str`` helper which catches a raising ``__str__``.
    return _safe_str(value, fallback=default)


# Round 19 HIGH (F-R19-1): a hostile plugin can override ``__repr__``
# (or ``__str__`` on an exception class) to RAISE rather than return a
# string. The previous defense layered ``_truncate_for_log`` and
# ``_sanitize_for_log`` over ``repr(obj)`` / ``str(exc)``, but the
# raising ``__repr__`` blows up BEFORE those wrappers see anything,
# crashing the discovery walk and skipping every plugin past the
# offending one. ``_safe_repr`` (and the sibling ``_safe_str``) wraps
# the conversion in a ``BaseException`` catch and returns a fixed
# fallback string. We catch ``BaseException`` -- not just ``Exception``
# -- so a hostile ``__repr__`` that raises ``SystemExit`` /
# ``KeyboardInterrupt`` / ``GeneratorExit`` cannot abuse the narrower
# guard to escape and abort discovery. The exception class name is
# included in the fallback so operators retain a useful breadcrumb for
# debugging without exposing arbitrary plugin-controlled bytes.
#
# Round 21 HIGH (F-R21-1): the breadcrumb interpolation itself goes
# through ``_safe_name`` so a hostile metaclass ``__getattribute__``
# that raises on ``__name__`` cannot crash the fallback path.
def _safe_repr(obj: object, *, fallback: str = "<repr raised>") -> str:
    """Best-effort ``repr(obj)`` that never propagates exceptions.

    Returns *fallback* (suffixed with the raising exception's type
    name) when ``repr()`` raises any ``BaseException`` subclass. The
    returned string is suitable to feed into ``_truncate_for_log`` /
    ``_sanitize_for_log`` for terminal-safe logging.

    Round 27 P0: also defends against the sibling vector where
    ``repr(obj)`` SUCCEEDS but returns a ``str``-SUBCLASS instance
    whose ``__len__`` / ``__bool__`` / ``__hash__`` / ``__str__`` is
    overridden to raise. Python's ``repr()`` builtin calls
    ``type(obj).__repr__(obj)`` and returns whatever that method
    returns -- including a ``str`` subclass. The R19 closure caught the
    raising-``__repr__`` case; this layer catches the
    returns-hostile-subclass case. Same primitive ``str.__str__`` coerce
    R26 used in ``_safe_str_attr``.
    """
    try:
        raw = repr(obj)
    except BaseException as exc:
        # Intentional ``BaseException`` catch: a hostile plugin's
        # ``__repr__`` can raise any ``BaseException`` subclass
        # (including ``SystemExit`` / ``KeyboardInterrupt`` /
        # ``GeneratorExit``). We MUST swallow them all here -- the
        # whole point of the helper is to neutralize that vector.
        # ``_safe_name`` keeps the breadcrumb access bulletproof against
        # a hostile metaclass that raises on ``__name__``.
        return f"{fallback}: {_safe_name(exc)}"
    # Round 27 P0: subclass-safe coerce. Even though Python's ``repr()``
    # builtin nominally returns ``str``, a hostile ``__repr__`` is
    # allowed to return a ``str``-SUBCLASS. Downstream consumers
    # (``_truncate_for_log``'s ``len(s)``, ``_sanitize_for_log``'s
    # ``isinstance(value, str)`` + ``.translate(...)``) then invoke the
    # subclass's raising dunder and abort the walk. ``str.__str__`` is
    # the unbound plain-``str`` dunder; calling it explicitly returns
    # the underlying primitive without invoking the subclass override.
    try:
        if isinstance(raw, str):
            return str.__str__(raw)
        return str(raw)
    except BaseException as exc:
        return f"{fallback}: {_safe_name(exc)}"


def _safe_str(obj: object, *, fallback: str = "<str raised>") -> str:
    """Best-effort ``str(obj)`` that never propagates exceptions.

    Same shape as :func:`_safe_repr` but for the ``str()`` conversion
    used on exception payloads at the load-error branch -- a hostile
    custom exception class can override ``__str__`` to raise just as
    easily as ``__repr__``.

    Round 27 P0: also defends against the sibling vector where
    ``str(obj)`` SUCCEEDS but returns a ``str``-SUBCLASS instance whose
    ``__len__`` / ``__bool__`` / ``__hash__`` / ``__str__`` is
    overridden to raise. Mirrors the closure in :func:`_safe_repr`.
    """
    try:
        raw = str(obj)
    except BaseException as exc:
        # Same intentional broad catch as ``_safe_repr`` -- a hostile
        # plugin's ``__str__`` can raise any ``BaseException``.
        # ``_safe_name`` keeps the breadcrumb access bulletproof against
        # a hostile metaclass that raises on ``__name__``.
        return f"{fallback}: {_safe_name(exc)}"
    # Round 27 P0: subclass-safe coerce. ``str()`` builtin calls
    # ``type(obj).__str__(obj)``; a hostile ``__str__`` can return a
    # ``str``-SUBCLASS whose ``__len__`` raises. ``_truncate_for_log``'s
    # ``len(s)`` then aborts the load-error branch. ``str.__str__``
    # bypasses the subclass override and returns the plain underlying
    # ``str``.
    try:
        if isinstance(raw, str):
            return str.__str__(raw)
        return str(raw)
    except BaseException as exc:
        return f"{fallback}: {_safe_name(exc)}"


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


PluginStatus = Literal["loaded", "incompatible_abi", "load_error", "duplicate_name"]


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

    def __post_init__(self) -> None:
        # Round 23 LOW (F-R23-6): every plugin-controlled string field
        # on this dataclass is cached in ``_DISCOVERED_PLUGINS_CACHE``
        # for the process lifetime. The CLI surfaces already truncate
        # at log-emission time, but a hostile sdist with 1000 entry
        # points and 10 MB ``ep.name`` / ``ep.value`` / distribution
        # ``name`` + ``version`` each could pin 40 GB resident purely
        # in the cache. Cap each plugin-controlled field at
        # ``_truncate_for_log``'s default 1024 chars matching the log-
        # emission cap. ``group`` and ``status`` are signet-controlled
        # constants and need no cap; ``error`` is already truncated at
        # construction time at every call-site (load_error /
        # incompatible_abi / duplicate_name).
        #
        # ``object.__setattr__`` is required because this dataclass is
        # frozen=True (so plain attribute assignment would raise
        # ``FrozenInstanceError``). This is the documented escape hatch
        # for ``__post_init__`` on a frozen dataclass.
        # Round 25 MED (F-R25-5): the previous ``isinstance(_val, str)``
        # gate accepted a ``str``-SUBCLASS whose ``__len__`` raises,
        # crashing the truncation step on the very first plugin. Worse,
        # it silently bypassed truncation for non-``str`` values (which
        # then crashed ``signet plugins list --json`` at JSON encode
        # time). Drop the gate and coerce-then-truncate unconditionally
        # via ``_safe_str_attr`` so every cached field is a plain
        # ``str`` of bounded length, regardless of what the plugin
        # entry-point returned.
        for _attr in ("name", "package", "package_version", "target"):
            _val = _safe_str_attr(self, _attr, default="")
            if len(_val) > 1024:
                _val = _truncate_for_log(_val)
            object.__setattr__(self, _attr, _val)
        # Round 27 MED: ``abi_declared`` is plugin-controlled too -- a
        # hostile ``CHECK_ABI_VERSION`` value can be an ``int``-SUBCLASS
        # whose ``__str__`` / ``__format__`` raises. The string-field
        # coerce above leaves ``abi_declared`` untouched, so the
        # subclass survives in the cache and crashes the CLI render path
        # (``signet plugins list`` -> ``_sanitize_for_terminal(abi)`` ->
        # ``str(value)``). Coerce to a plain ``int`` (or ``None``) here
        # via ``int.__int__`` -- the unbound dunder bypasses any
        # subclass override and returns the underlying primitive.
        if self.abi_declared is not None:
            try:
                _abi: int | None = int.__int__(self.abi_declared)
            except BaseException:
                _abi = None
            object.__setattr__(self, "abi_declared", _abi)


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
            # Round 25 HIGH (F-R25-1/2): ``ep.name``/``ep.value`` are
            # plugin-controlled string-typed attributes; coerce to plain
            # ``str`` once at the top of the iteration so every downstream
            # use (dict key, ``or`` fallback, ``setdefault`` tuple key,
            # f-string interpolation, ``DiscoveredPlugin.__post_init__``
            # truncation) sees a hashable, len-able, bool-able primitive.
            ep_name = _safe_str_attr(ep, "name", default="")
            ep_value = _safe_str_attr(ep, "value", default="")
            # ``common`` is unpacked into ``DiscoveredPlugin(...)`` via
            # ``**common`` at five different sites below. mypy can't
            # narrow ``dict[str, <inferred-mixed>]`` per-key when
            # unpacked, so we widen to ``dict[str, Any]`` to suppress
            # the false-positive errors; the actual per-field types are
            # checked by ``DiscoveredPlugin.__post_init__`` at runtime.
            common: dict[str, Any] = {
                "group": group,
                "name": ep_name,
                "package": pkg,
                "package_version": ver,
                "target": ep_value,
                "abi_required": CHECK_ABI_VERSION,
            }

            try:
                obj = ep.load()
            except (KeyboardInterrupt, SystemExit):
                # Round 19 MED (F-R19-2): genuine operator-initiated
                # Ctrl+C (``KeyboardInterrupt``) and process-exit
                # (``SystemExit``) signals must propagate so the user
                # can interrupt a slow discovery and so a deliberate
                # ``sys.exit()`` from an entry-point loader still
                # works. We re-raise BEFORE recording an error row --
                # there is no "load failure" semantic for a signal the
                # operator deliberately raised.
                raise
            except BaseException as exc:
                # Round 19 MED (F-R19-2): widened from ``except
                # Exception`` to ``except BaseException`` (minus the
                # propagating signals above) so a hostile plugin
                # cannot abort the entire discovery walk by raising
                # ``GeneratorExit``, ``MemoryError``, or any other
                # non-``Exception`` ``BaseException`` subclass on
                # import. The previous ``except Exception`` let those
                # escape, skipping every later entry point in the
                # group and surfacing a raw traceback through
                # ``signet plugins doctor`` instead of a structured
                # ``load_error`` row.
                #
                # Round 9 MED: ep.name and the exception message both
                # originate in plugin code/metadata and may carry ANSI
                # control bytes. Sanitize before logging (the default
                # handler writes to stderr -- a terminal-render surface).
                # Round 17 LOW (F-R17-2): pre-cap the exception payload
                # with ``_truncate_for_log`` the same way the other two
                # ``_sanitize_for_log`` sites do. A hostile plugin's
                # ``ep.load()`` can raise an exception whose
                # ``__str__`` returns 10 MB+ of escape bytes; without
                # the cap the per-codepoint sanitize stalls for tens
                # of seconds AND a 40 MB rendered string is cached in
                # ``_DISCOVERED_PLUGINS_CACHE.error`` for the process
                # lifetime, then re-rendered to stderr on every
                # ``plugins list`` / ``plugins doctor`` invocation. We
                # cache the SAME truncated form in the ``error`` field
                # so the cap covers both the live log line and the
                # cached payload.
                # Round 19 HIGH (F-R19-1): a hostile exception class
                # can override ``__str__`` to raise. ``_safe_str``
                # catches that and substitutes a fallback string so
                # discovery does not abort mid-walk.
                # Round 21 HIGH (F-R21-2): ``type(exc).__name__`` is
                # attacker-controlled -- a hostile metaclass
                # ``__getattribute__`` can raise on ``__name__`` and
                # crash the discovery walk from inside this except
                # branch. ``_safe_name`` routes the access through a
                # ``BaseException`` catch with a constant-string
                # fallback. Both the live log line AND the cached
                # ``error`` payload go through the helper.
                exc_str_safe = _sanitize_for_log(_truncate_for_log(_safe_str(exc)))
                exc_name_safe = _safe_name(exc)
                logger.warning(
                    "signet plugin %r (%s) failed to load: %s: %s",
                    _sanitize_for_log(_truncate_for_log(ep_name)),
                    _sanitize_for_log(_truncate_for_log(group)),
                    exc_name_safe,
                    exc_str_safe,
                )
                results.append(
                    DiscoveredPlugin(
                        **common,
                        status="load_error",
                        abi_declared=None,
                        error=f"{exc_name_safe}: {exc_str_safe}",
                        obj=None,
                    )
                )
                continue

            if group == "signet.checks":
                # Round 23 HIGH (F-R23-3): ``isinstance(obj, type)`` reads
                # ``obj.__class__`` and ``issubclass(obj, Check)`` reads
                # the MRO -- both are descriptor / metaclass surfaces a
                # hostile plugin can hijack to raise ``BaseException``.
                # The previous code only wrapped ``ep.load()`` in a
                # ``try``; a raise here escaped that guard and aborted
                # the entire discovery walk. Routing through
                # ``_safe_isinstance`` / ``_safe_issubclass`` returns
                # ``False`` on any ``BaseException`` so the non-Check
                # branch records a structured ``load_error`` row and
                # discovery continues.
                if not (_safe_isinstance(obj, type) and _safe_issubclass(obj, Check)):
                    # Round 14 INFO: a hostile plugin can override
                    # ``__repr__`` via a metaclass (or supply a non-
                    # ``Check`` object whose class has a malicious
                    # ``__repr__``). Python's default ``str.__repr__``
                    # escapes control bytes but a custom ``__repr__`` is
                    # plugin-controlled, so ``%r`` of ``obj`` cannot be
                    # trusted. Sanitize the ``repr()`` OUTPUT (not the
                    # object) before it reaches the stderr stream
                    # handler. Same defense applies to the structured
                    # ``msg`` stored in ``error``.
                    # Round 15 LOW (F-R15-2): pre-cap the ``repr()``
                    # length so a hostile multi-MB ``__repr__`` cannot
                    # stall discovery via the sanitizer's per-codepoint
                    # translation pass.
                    # Round 19 HIGH (F-R19-1): a hostile metaclass /
                    # class can override ``__repr__`` to raise. Use
                    # ``_safe_repr`` so the conversion never propagates
                    # an exception out of the discovery walk.
                    obj_repr_safe = _sanitize_for_log(_truncate_for_log(_safe_repr(obj)))
                    msg = f"resolved object {obj_repr_safe} is not a Check subclass"
                    logger.warning(
                        "signet plugin %r resolved to %s which is not a Check subclass; skipping",
                        _sanitize_for_log(_truncate_for_log(ep_name)),
                        obj_repr_safe,
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

                # Round 23 HIGH (F-R23-2): ``getattr(obj, "CHECK_ABI_VERSION",
                # None)`` only swallows ``AttributeError``. A hostile
                # metaclass ``__getattribute__`` that raises any other
                # ``BaseException`` on this access aborted the discovery
                # walk entirely. ``_safe_getattr`` widens the catch to
                # ``BaseException`` and returns the same ``None`` sentinel
                # the stdlib ``getattr(..., default)`` contract returns,
                # routing the failure through the non-integer-ABI branch.
                declared = _safe_getattr(obj, "CHECK_ABI_VERSION", None)
                # Round 23 HIGH (F-R23-3): ``isinstance(declared, int)``
                # reads ``declared.__class__`` via the descriptor
                # protocol -- a hostile ``CHECK_ABI_VERSION`` value with
                # a raising ``__class__`` property crashes the gate
                # itself. ``_safe_isinstance`` routes the failure into
                # the non-integer-ABI branch with a structured row.
                # Round 27 HIGH: coerce ``declared`` to a plain ``int`` AFTER
                # the isinstance gate -- ``_safe_isinstance(declared, int)``
                # accepts an ``int``-SUBCLASS whose ``__ne__`` /
                # ``__format__`` / ``__str__`` is overridden to raise. The
                # hostile subclass then crashes the ``declared !=
                # CHECK_ABI_VERSION`` comparison (dispatches to
                # ``declared.__ne__``), the f-string ``{declared}``
                # interpolation (dispatches to ``declared.__format__``), and
                # later the CLI's ``str(abi_declared)`` rendering. Same root
                # family as the str-subclass closures: ``int.__int__`` is
                # the unbound plain-``int`` dunder; calling it explicitly
                # returns the underlying primitive without invoking the
                # subclass ``__int__`` override. ``bool`` is an ``int``
                # subclass too but a builtin -- no hostile override risk --
                # so we leave it in the gate-true branch (``int.__int__``
                # coerces ``True`` -> ``1`` and ``False`` -> ``0``).
                if _safe_isinstance(declared, int):
                    try:
                        declared = int.__int__(declared)  # type: ignore[arg-type]
                    except BaseException:
                        # Hostile ``int.__int__`` override raised. Route
                        # through incompatible_abi via the gate below by
                        # substituting a non-int sentinel so the
                        # ``_safe_isinstance`` check fails. (``None`` is
                        # the canonical "no integer ABI declared" sentinel
                        # already used at the load-error branch.)
                        declared = None
                if not _safe_isinstance(declared, int):
                    # Round 9 MED: obj.__name__ is class-controlled; the
                    # declared value (via repr) is auto-escaped.
                    # Round 14 INFO: ``declared`` may be a hostile
                    # instance whose class overrides ``__repr__``, so
                    # ``%r`` of it is plugin-controlled. Sanitize the
                    # repr output before interpolating.
                    # Round 15 LOW (F-R15-2): pre-cap the ``repr()``
                    # length so a hostile multi-MB ``__repr__`` cannot
                    # stall discovery via the sanitizer's per-codepoint
                    # translation pass.
                    # Round 19 HIGH (F-R19-1): a hostile
                    # ``CHECK_ABI_VERSION`` value (e.g. an instance
                    # whose class overrides ``__repr__``) can raise.
                    # ``_safe_repr`` neutralizes that case.
                    declared_repr_safe = _sanitize_for_log(_truncate_for_log(_safe_repr(declared)))
                    # Round 21 HIGH (F-R21-2): ``obj.__name__`` is
                    # attacker-controlled -- a hostile metaclass can
                    # override ``__getattribute__`` to raise on
                    # ``__name__`` access and crash the discovery walk.
                    # ``_safe_name`` routes the access through a
                    # ``BaseException`` catch with a constant-string
                    # fallback.
                    obj_name_safe = _safe_name(obj)
                    msg = (
                        f"plugin class "
                        f"{_sanitize_for_log(_truncate_for_log(obj_name_safe))} "
                        f"did not declare an integer "
                        f"CHECK_ABI_VERSION (got {declared_repr_safe})"
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
                    # Round 9 MED: sanitize ep.name before message build.
                    # Round 14 INFO: ``declared`` is a real int on this
                    # branch (isinstance gate above) so ``%d`` is the
                    # safer interpolation -- no ``__repr__`` surface.
                    msg = (
                        f"plugin "
                        f"{_sanitize_for_log(_truncate_for_log(ep_name))!r} "
                        f"declares CHECK_ABI_VERSION={declared}; "
                        f"signet requires {CHECK_ABI_VERSION}"
                    )
                    logger.warning("%s; refusing to load", msg)
                    results.append(
                        DiscoveredPlugin(
                            **common,
                            status="incompatible_abi",
                            # ``declared`` is narrowed to ``int`` by the
                            # ``_safe_isinstance(declared, int)`` gate
                            # plus the ``int.__int__`` coerce above, but
                            # the mypy narrower can't track those
                            # branches. ``cast`` makes the intent
                            # explicit at the construction site.
                            abi_declared=cast(int, declared),
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
                # Round 25 HIGH (F-R25-4): use the plain-``str`` ``ep_name``
                # local, not ``ep.name`` directly. A hostile ``str``-
                # subclass with raising ``__hash__`` would crash the dict
                # assignment otherwise.
                checks[ep_name] = obj
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
        package_labels = [results[i].package or "<unknown distribution>" for i in indices]
        for idx in indices:
            others = tuple(
                package_labels[j] for j, other_idx in enumerate(indices) if other_idx != idx
            )
            this_pkg = results[idx].package or "<unknown distribution>"
            # Round 9 MED: entry-point name + group + package names all
            # originate in attacker-influenceable distribution metadata.
            # Sanitize before message build so the stored ``error`` field
            # and the logger line are both terminal-safe. The ``!r``
            # repr() form provides additional defense in depth.
            msg = (
                f"entry-point name "
                f"{_sanitize_for_log(_truncate_for_log(results[idx].name))!r} "
                f"in group "
                f"{_sanitize_for_log(_truncate_for_log(results[idx].group))!r} "
                f"is also registered by: "
                f"{', '.join(_sanitize_for_log(_truncate_for_log(o)) for o in others)} "
                f"(this entry: {_sanitize_for_log(_truncate_for_log(this_pkg))})"
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

    Round 23 HIGH (F-R23-2): all three ``getattr`` calls here read
    attributes on plugin-controlled objects (``EntryPoint`` subclasses
    and ``Distribution`` providers from custom importlib.metadata
    backends in hot-reload / test paths). A raising metaclass
    ``__getattribute__`` or property descriptor on any of them would
    propagate ``BaseException`` out and abort the entire discovery
    walk BEFORE the ``ep.load()`` try-block had a chance to record a
    row. ``_safe_getattr`` catches ``BaseException`` and falls back
    to the documented sentinel.
    """
    dist = _safe_getattr(ep, "dist", None)
    if dist is None:
        return ("", "")
    # Round 25 HIGH (F-R25-3): a hostile ``Distribution`` provider can
    # return a ``str``-SUBCLASS instance whose ``__bool__`` raises. The
    # previous R23 code path used ``_safe_getattr(...) or ""`` which
    # invokes the subclass ``__bool__``. ``_safe_str_attr`` returns a
    # plain ``str`` regardless of subclass, so the ``or`` short-circuit
    # below is safe -- but we drop ``or ""`` entirely since the helper
    # already defaults to ``""`` on every failure shape.
    name = _safe_str_attr(dist, "name", default="")
    version = _safe_str_attr(dist, "version", default="")
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
