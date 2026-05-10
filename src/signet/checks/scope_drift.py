"""ScopeDriftCheck -- abort when output exceeds the originally-approved scope.

Authorization granted at request time has bounds. A request approved
for 200 output tokens shouldn't silently become a 50,000-token output;
a request approved against an UNCLASS classification shouldn't drift
into emitting SECRET-tagged content; a tool call approved with arguments
``{"path": "/tmp/x"}`` shouldn't morph into ``{"path": "/etc/passwd"}``
partway through generation.

ScopeDriftCheck enforces these bounds by capturing the *approved scope*
at the end of ADMISSION and re-checking against the actual output during
INSPECTION. When the output drifts outside the bound, the stream is
aborted. The remedy is for the caller to re-issue the request with the
expanded scope explicitly approved; the gate refuses to silently widen.

Three drift dimensions are checked out of the box:

1. **Token-count drift**: output tokens exceed
   ``max_tokens * (1 + tolerance)``.
2. **Length drift** (character-level): output character count exceeds
   ``hard_char_cap`` (default 4x the per-token-2-char rule of thumb on
   ``max_tokens``). **Requires ``max_tokens`` to be a positive integer
   in the request body** -- without it the character cap has no
   anchor and length drift is not enforced (C7.3). Callers that need
   length drift detection MUST set ``max_tokens`` on every request.
3. **Content drift via classification re-scan**: output contains marker
   strings (e.g. ``"SECRET//NOFORN"``) above the request's declared
   classification. Cross-chunk markers are detected: a marker split
   across two streamed chunks (``"(S//"`` then ``"NF)"``) is caught
   on the second chunk because the matcher scans
   ``ctx.accumulated_text`` (C7.2).

Marker false-positive surface: matching is literal-substring. A model
explaining "the SECRET//NOFORN handling rules are…" in legitimately
UNCLASS training material will trip the check. Override the marker
table via the ``markers`` constructor argument when your domain has
benign uses of the strings, or set ``check_classification_drift=False``
if your deployment doesn't use classification at all.

Adding more drift dimensions is a matter of subclassing and overriding
:meth:`inspect_response_chunk`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from signet.core.check import Check, CheckResult
from signet.core.context import ResponseContext, get_header_ci
from signet.core.stage import Stage

# Markers we look for in output that imply a classification level. Same
# alias map shape as ClassificationGateCheck but kept local to avoid
# coupling between checks.
#
# v0.1.7 expansion: the v0.1.6 dictionary missed the most obvious
# operator spellings -- plain ``(SECRET)``, ``(TOP SECRET)``,
# ``(CONFIDENTIAL)``, ``(C)``, the lowercase variants of every slash
# marker, and the standalone caveats (``//NOFORN``, ``//FVEY``,
# ``//ORCON``, ``//IMCON``). Matching is now case-insensitive by default
# (see :attr:`ScopeDriftCheck.case_sensitive`).
#
# Levels follow the USG ladder: 0=UNCLASS, 1=CUI/FOUO, 2=SECRET, 3=TS,
# 4=TS/SCI. Standalone caveats inherit a SECRET-level floor because a
# ``//NOFORN`` qualifier alone implies the body is at least classified
# even when the caveat is paired with a missing explicit level.
_CLASSIFICATION_MARKERS: dict[str, int] = {
    # Slash-form full markers
    "SECRET//NOFORN": 2,
    "SECRET//REL": 2,
    "TOP SECRET//SCI": 4,
    "TS//SCI": 4,
    # Parenthesized abbreviations
    "(S)": 2,
    "(S//NF)": 2,
    "(TS)": 3,
    "(TS//SCI)": 4,
    "(C)": 1,
    "(U)": 0,
    "(U//FOUO)": 1,
    # Plain parenthesized full-spellings -- the most obvious surface a
    # naive model trips on first.
    "(SECRET)": 2,
    "(TOP SECRET)": 3,
    "(CONFIDENTIAL)": 1,
    # CUI / FOUO family
    "CUI//": 1,
    "FOUO": 1,
    # Standalone caveats. A model that emits ``//NOFORN`` on its own
    # has implicitly leaked at least classification-level intent.
    "//NOFORN": 2,
    "//FVEY": 2,
    "//ORCON": 2,
    "//IMCON": 2,
}


@dataclass
class ScopeDriftCheck(Check):
    """INSPECTION-stage check: abort when output exceeds approved scope.

    Args:
        token_tolerance: Fraction by which output may exceed the
            requested ``max_tokens`` before drift is declared. 0.10
            allows up to 10% over, accommodating tokenizer differences
            between upstreams. Defaults to 0.10.
        char_per_token_estimate: Average characters per token. Used to
            convert ``max_tokens`` into a hard character cap. Defaults
            to 4 (English-typical).
        check_classification_drift: If ``True``, scan output for marker
            strings implying a higher classification than the request
            declared. Requires the request to have a recognized
            ``X-Classification`` header.
        markers: Override the built-in marker → level table. Pass your
            own ``{marker_string: level_int}`` dict for non-USG
            classification systems or to suppress markers that produce
            false positives in your corpus. ``None`` (default) uses
            the built-in USG markers.
    """

    name = "scope_drift"
    stage = Stage.INSPECTION

    token_tolerance: float = 0.10
    char_per_token_estimate: int = 4
    check_classification_drift: bool = True
    markers: dict[str, int] | None = None
    case_sensitive: bool = False
    """Whether marker matching respects case. Defaults to ``False`` --
    a model that hallucinates ``secret//noforn`` should still trip the
    drift detector. Set ``True`` if your corpus contains benign
    lowercase mentions of marker-like substrings (e.g. legal review
    drafts referencing ``"the secret//noforn handling rules"``)."""

    _classification_pattern: re.Pattern[str] = field(init=False, repr=False)
    _marker_levels: dict[str, int] = field(init=False, repr=False)
    # Lowercase-keyed view for case-insensitive lookups. ``_marker_levels``
    # preserves the configured casing so it remains operator-readable.
    _marker_levels_ci: dict[str, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.token_tolerance < 0:
            raise ValueError("token_tolerance must be >= 0")
        if self.char_per_token_estimate < 1:
            raise ValueError("char_per_token_estimate must be >= 1")
        self._marker_levels = (
            dict(self.markers) if self.markers is not None else dict(_CLASSIFICATION_MARKERS)
        )
        self._marker_levels_ci = {k.lower(): v for k, v in self._marker_levels.items()}
        # Pre-compile alternation of markers, longest-first so multi-token
        # markers match before substrings of themselves. Matching is
        # case-insensitive by default -- catches the lowercase
        # ``secret//noforn`` and ``Secret//NoForN`` variants that a
        # hallucinating model frequently emits, at the cost of accepting
        # a slightly broader false-positive surface.
        ordered = sorted(self._marker_levels, key=len, reverse=True)
        escaped = [re.escape(m) for m in ordered]
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self._classification_pattern = (
            re.compile("|".join(escaped), flags) if escaped else re.compile(r"(?!x)x")
        )

    # Scratch keys threaded through ``ResponseContext.scratch`` so the
    # cumulative-scan path doesn't redo work on every chunk. Per-context
    # state -- a fresh response gets a fresh scratch dict.
    _LAST_POS_KEY = "_scope_drift_last_pos"

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        # Token-count drift
        max_tokens = ctx.request.body.get("max_tokens")
        if isinstance(max_tokens, int) and max_tokens > 0:
            char_cap = int(max_tokens * self.char_per_token_estimate * (1 + self.token_tolerance))
            if len(ctx.accumulated_text) > char_cap:
                return CheckResult.block(
                    f"output character count {len(ctx.accumulated_text)} "
                    f"exceeds scope-drift cap {char_cap} "
                    f"(max_tokens={max_tokens} * {self.char_per_token_estimate} * "
                    f"(1+{self.token_tolerance}))",
                    drift_kind="token_count",
                    accumulated_chars=len(ctx.accumulated_text),
                    cap=char_cap,
                )

        # Classification drift.
        #
        # S1 (v0.1.7 follow-up): the v0.1.6 / v0.1.7 implementation only
        # scanned ``ctx.accumulated_text``. ``ResponseContext.extend_text``
        # enforces a 1 MiB cap to bound proxy memory -- once the cap is
        # hit, subsequent chunks are dropped from the accumulated buffer.
        # A leaker that pads with 1 MiB of benign content and then ships
        # the classification marker in a single late chunk slipped past
        # the check because that chunk never landed in ``accumulated_text``.
        #
        # Fix strategy: prefer the accumulated buffer as the scan
        # source (so the proxy's SSE-line filter -- ``inspect_all_sse_
        # lines`` -- still gates what we see, including the v0.1.7 S6
        # contract that ``event:`` / ``id:`` lines are out of scope by
        # default). When the cap is saturated -- ``accumulated_text_
        # truncated=True`` AND the buffer didn't grow on this call --
        # the chunk parameter is the only signal, so we scan it
        # directly. The cap is meant to bound memory, not enforcement.
        #
        # De-dup: scan only the new portion of ``accumulated_text`` past
        # ``ctx.scratch[_LAST_POS_KEY]``, with an overlap of
        # ``longest_marker - 1`` chars so a marker straddling the
        # boundary is fully visible.
        if self.check_classification_drift:
            request_level = self._declared_classification(ctx)

            last_pos = ctx.scratch.get(self._LAST_POS_KEY, 0)
            longest_marker = max((len(m) for m in self._marker_levels), default=0)
            overlap = max(0, longest_marker - 1)
            scan_start = max(0, last_pos - overlap)
            tail = ctx.accumulated_text[scan_start:]

            # Update last-pos BEFORE any early return so a no-match
            # call still advances the cursor and the next call doesn't
            # re-scan the same content.
            ctx.scratch[self._LAST_POS_KEY] = len(ctx.accumulated_text)

            # Cumulative scan -- the canonical path. Respects the
            # proxy's SSE-line filtering because only the extracted
            # content (``_extract_sse_content`` output) lands in
            # ``accumulated_text``.
            if tail:
                tail_match = self._classification_pattern.search(tail)
                if tail_match:
                    result = self._classification_block(tail_match, request_level)
                    if result is not None:
                        return result

            # Chunk-direct scan -- the S1 safety net. Only runs when
            # the accumulated-text cap has been hit on this context
            # (``accumulated_text_truncated=True``). At that point the
            # buffer is missing content and we'd otherwise allow a
            # leaker who padded with > 1 MiB of benign output. Gating
            # on the truncation flag preserves the proxy's
            # ``inspect_all_sse_lines=False`` semantics on the common
            # path -- raw SSE prelude lines are only scanned once the
            # buffer-based defense has demonstrably stopped working.
            if ctx.accumulated_text_truncated and chunk:
                chunk_match = self._classification_pattern.search(chunk)
                if chunk_match:
                    result = self._classification_block(chunk_match, request_level)
                    if result is not None:
                        return result

        return CheckResult.allow()

    def _classification_block(
        self, match: re.Match[str], request_level: int
    ) -> CheckResult | None:
        """Resolve ``match`` to a BLOCK CheckResult, or ``None`` when the
        marker level is compatible with the request's declared level.

        Factored out of :meth:`inspect_response_chunk` so the chunk-direct
        and cumulative-scan paths share identical resolution semantics.
        """
        marker = match.group(0)
        # Look up via the case-folded view so a lowercase
        # ``secret//noforn`` match still resolves to its
        # SECRET-level configured value. ``99`` is the
        # paranoid fallback for an unrecognized match (which
        # shouldn't happen since the regex is built from the
        # same dict, but keeps the invariant safe).
        if self.case_sensitive:
            marker_level = self._marker_levels.get(marker)
        else:
            marker_level = self._marker_levels_ci.get(marker.lower())
        if marker_level is None:
            marker_level = 99
        if marker_level > request_level:
            return CheckResult.block(
                f"output marker {marker!r} implies classification level "
                f"{marker_level} > request-declared level {request_level}",
                drift_kind="classification",
                marker=marker,
                marker_level=marker_level,
                request_level=request_level,
            )
        return None

    @staticmethod
    def _declared_classification(ctx: ResponseContext) -> int:
        """Map the request's X-Classification header to a numeric level."""
        v = get_header_ci(ctx.request.headers, "X-Classification")
        if not v:
            return 0  # UNCLASS default
        norm = v.upper()
        return {
            "UNCLASS": 0,
            "UNCLASSIFIED": 0,
            "U": 0,
            "CUI": 1,
            "FOUO": 1,
            "SECRET": 2,
            "S": 2,
            "TS": 3,
            "TOP SECRET": 3,
            "TS/SCI": 4,
            "TS-SCI": 4,
            "TS_SCI": 4,
            "SCI": 4,
        }.get(norm, 0)
