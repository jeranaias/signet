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
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext
from signet.core.stage import Stage


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
    """

    pattern: str
    action: str = "block"
    replacement: str = "[REDACTED]"
    label: str = "match"

    def __post_init__(self) -> None:
        if self.action not in ("block", "redact"):
            raise ValueError(f"action must be 'block' or 'redact', got {self.action!r}")


def _compile_patterns(patterns: Iterable[Pattern]) -> tuple[tuple[Pattern, re.Pattern[str]], ...]:
    """Compile each pattern once at construction; raise on bad regex."""
    out: list[tuple[Pattern, re.Pattern[str]]] = []
    for p in patterns:
        try:
            out.append((p, re.compile(p.pattern)))
        except re.error as exc:
            raise ValueError(f"invalid regex for pattern {p.label!r}: {exc}") from exc
    return tuple(out)


def _scan(
    text: str,
    compiled: tuple[tuple[Pattern, re.Pattern[str]], ...],
) -> tuple[CheckResult, ...]:
    """Run every compiled pattern against ``text``.

    Returns one CheckResult per match. Empty if no matches.
    """
    results: list[CheckResult] = []
    for spec, regex in compiled:
        if not regex.search(text):
            continue
        if spec.action == "block":
            results.append(
                CheckResult.block(
                    f"pattern {spec.label!r} matched",
                    pattern_label=spec.label,
                )
            )
        else:  # redact
            redacted = regex.sub(spec.replacement, text)
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
