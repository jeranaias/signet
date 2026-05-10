"""RegexContentCheck — block or redact patterns in input or output.

A general-purpose pattern matcher with two modes:

* **Input mode** (ADMISSION stage): scan the request body. Block or
  redact before the model ever sees the content.
* **Output mode** (INSPECTION stage): scan streamed response chunks
  and the accumulated text. Block aborts the stream; redact replaces
  the matched span in subsequent chunks.

Because the same logic is wanted at two different stages, we expose two
classes — :class:`RegexContentCheck` for input and
:class:`RegexOutputCheck` for output — both backed by the same matcher.
This keeps the stage declaration explicit at registration time rather
than via a constructor flag (which would defeat
:class:`signet.core.pipeline.Pipeline`'s stage-based ordering).

Pattern format: any Python ``re`` regex. Compiled once at construction.

**ReDoS protection (v0.1.7).** When the third-party ``regex`` package
is installed, every match is run with a per-pattern wall-clock
``timeout_seconds`` (default 0.5s). Pathological inputs against
catastrophic-backtracking patterns (``^(a+)+$`` against
``"a"*30 + "X"``) are interrupted mid-search and produce a BLOCK
result rather than holding the asyncio event loop for tens of
seconds. Without ``regex`` the check falls back to ``re``; the
timeout is best-effort and an attacker-controlled pattern can still
hang the loop. ``pip install regex`` (or ``signet-sign[regex]``) for
the production-grade behaviour.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext
from signet.core.stage import Stage

# Prefer the third-party ``regex`` module when available; only it
# supports a ``timeout`` kwarg that interrupts the C-level matcher
# mid-search. Without it, ``re.search`` is uninterruptible from Python
# and a pathological backtracking pattern hangs the asyncio loop.
#
# The ``regex`` package raises Python's built-in :class:`TimeoutError`
# when a search exceeds the configured wall-clock budget — there is
# no ``regex.TimeoutError`` attribute. We bind the matcher to that
# concrete type so the fallback ``re`` path doesn't accidentally
# swallow unrelated ``TimeoutError`` instances raised elsewhere.
try:  # pragma: no cover - import-time branch
    import regex as _regex_module

    _HAS_REGEX_TIMEOUT = True
    _RegexTimeoutError: type[BaseException] = TimeoutError
except ImportError:  # pragma: no cover - import-time branch
    _regex_module = re  # type: ignore[assignment]
    _HAS_REGEX_TIMEOUT = False

    class _NeverRaisedTimeout(Exception):
        """Stand-in so ``except`` blocks compile without ``regex``."""

    _RegexTimeoutError = _NeverRaisedTimeout


@dataclass(frozen=True, slots=True)
class Pattern:
    """One pattern + its action.

    Attributes:
        pattern: The regex source. Compiled once at construction time.
        action: Either ``"block"`` (refuse the request) or ``"redact"``
            (replace the matched span with ``replacement``).
        replacement: Replacement string used when ``action == "redact"``.
            Ignored otherwise.
        label: Short tag used in audit reasons and metadata. Pick
            something policy-meaningful, e.g. ``"ssn"``, ``"api-key"``,
            ``"profanity"``.
        timeout_seconds: Wall-clock cap on a single search against this
            pattern. Defaults to 0.5s. Only honored when the
            third-party ``regex`` package is installed; the standard
            library ``re`` cannot be interrupted from Python.
    """

    pattern: str
    action: str = "block"
    replacement: str = "[REDACTED]"
    label: str = "match"
    timeout_seconds: float = 0.5

    def __post_init__(self) -> None:
        if self.action not in ("block", "redact"):
            raise ValueError(f"action must be 'block' or 'redact', got {self.action!r}")
        if self.timeout_seconds <= 0:
            raise ValueError(
                f"timeout_seconds must be > 0, got {self.timeout_seconds!r}"
            )


def _compile_patterns(patterns: Iterable[Pattern]) -> tuple[tuple[Pattern, Any], ...]:
    """Compile each pattern once at construction; raise on bad regex.

    Uses the ``regex`` module when present so the compiled pattern
    supports the ``timeout=`` kwarg at search time. Falls back to the
    standard library ``re`` when ``regex`` isn't installed; in that
    fallback path patterns are still compiled but cannot be
    interrupted mid-match.
    """
    out: list[tuple[Pattern, Any]] = []
    for p in patterns:
        try:
            compiled = _regex_module.compile(p.pattern)
        except (_regex_module.error, re.error) as exc:  # type: ignore[attr-defined]
            raise ValueError(f"invalid regex for pattern {p.label!r}: {exc}") from exc
        out.append((p, compiled))
    return tuple(out)


def _scan(
    text: str,
    compiled: tuple[tuple[Pattern, Any], ...],
) -> tuple[CheckResult, ...]:
    """Run every compiled pattern against ``text``.

    Returns one CheckResult per match. Empty if no matches. A pattern
    that times out (``regex.TimeoutError``) produces a BLOCK result
    flagged with ``redos_timeout=True`` — fail-closed against
    catastrophic-backtracking inputs that an attacker can craft against
    operator-supplied patterns.
    """
    results: list[CheckResult] = []
    for spec, regex_pattern in compiled:
        try:
            if _HAS_REGEX_TIMEOUT:
                match = regex_pattern.search(text, timeout=spec.timeout_seconds)
            else:
                match = regex_pattern.search(text)
        except _RegexTimeoutError:
            results.append(
                CheckResult.block(
                    f"pattern {spec.label!r} timed out (potential ReDoS)",
                    pattern_label=spec.label,
                    redos_timeout=True,
                    timeout_seconds=spec.timeout_seconds,
                )
            )
            continue
        if not match:
            continue
        if spec.action == "block":
            results.append(
                CheckResult.block(
                    f"pattern {spec.label!r} matched",
                    pattern_label=spec.label,
                )
            )
        else:  # redact
            try:
                if _HAS_REGEX_TIMEOUT:
                    redacted = regex_pattern.sub(
                        spec.replacement, text, timeout=spec.timeout_seconds
                    )
                else:
                    redacted = regex_pattern.sub(spec.replacement, text)
            except _RegexTimeoutError:
                results.append(
                    CheckResult.block(
                        f"pattern {spec.label!r} timed out during redact (potential ReDoS)",
                        pattern_label=spec.label,
                        redos_timeout=True,
                        timeout_seconds=spec.timeout_seconds,
                    )
                )
                continue
            results.append(
                CheckResult.redact(
                    redacted,
                    f"pattern {spec.label!r} redacted",
                    pattern_label=spec.label,
                )
            )
    return tuple(results)


def _extract_input_text(body: dict[str, Any]) -> str:
    """Best-effort extraction of human-readable text from an OpenAI-shaped
    request body. Concatenates content of every message; ignores tool calls
    and other non-text fields."""
    parts: list[str] = []
    for msg in body.get("messages", ()):
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # OpenAI vision-style: list of content parts
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(str(part.get("text", "")))
    return "\n".join(parts)


class RegexContentCheck(Check):
    """ADMISSION-stage scanner: applies patterns to the request body."""

    name = "regex_content"
    stage = Stage.ADMISSION

    def __init__(self, patterns: Iterable[Pattern]) -> None:
        self._compiled = _compile_patterns(patterns)

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        text = _extract_input_text(ctx.body)
        if not text:
            return CheckResult.allow()
        results = _scan(text, self._compiled)
        if not results:
            return CheckResult.allow()
        # First non-allow wins (block beats redact in ordering by giving
        # block patterns earlier registration). The proxy applies redact
        # by replacing body content; block aborts.
        return results[0]


class RegexOutputCheck(Check):
    """INSPECTION-stage scanner: applies patterns to streaming output."""

    name = "regex_output"
    stage = Stage.INSPECTION

    def __init__(self, patterns: Iterable[Pattern]) -> None:
        self._compiled = _compile_patterns(patterns)

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        # Scan the cumulative text so patterns spanning chunk boundaries
        # are still caught. The matcher returns the first non-allow.
        results = _scan(ctx.accumulated_text, self._compiled)
        if not results:
            return CheckResult.allow()
        return results[0]
