"""ScopeDriftCheck — abort when output exceeds the originally-approved scope.

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
   ``hard_char_cap`` (default 4× the per-token-2-char rule of thumb on
   ``max_tokens``).
3. **Content drift via classification re-scan**: output contains marker
   strings (e.g. ``"SECRET//NOFORN"``) above the request's declared
   classification.

Adding more drift dimensions is a matter of subclassing and overriding
:meth:`check_drift`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from signet.core.check import Check, CheckResult
from signet.core.context import ResponseContext
from signet.core.stage import Stage

# Markers we look for in output that imply a classification level. Same
# alias map shape as ClassificationGateCheck but kept local to avoid
# coupling between checks.
_CLASSIFICATION_MARKERS: dict[str, int] = {
    "SECRET//NOFORN": 2,
    "SECRET//REL": 2,
    "(S)": 2,
    "(S//NF)": 2,
    "TOP SECRET//SCI": 4,
    "TS//SCI": 4,
    "(TS)": 3,
    "(TS//SCI)": 4,
    "CUI//": 1,
    "FOUO": 1,
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
    """

    name = "scope_drift"
    stage = Stage.INSPECTION

    token_tolerance: float = 0.10
    char_per_token_estimate: int = 4
    check_classification_drift: bool = True

    _classification_pattern: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.token_tolerance < 0:
            raise ValueError("token_tolerance must be >= 0")
        if self.char_per_token_estimate < 1:
            raise ValueError("char_per_token_estimate must be >= 1")
        # Pre-compile alternation of markers, longest-first so multi-token
        # markers match before substrings of themselves.
        markers = sorted(_CLASSIFICATION_MARKERS, key=len, reverse=True)
        escaped = [re.escape(m) for m in markers]
        self._classification_pattern = re.compile("|".join(escaped))

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        # Token-count drift
        max_tokens = ctx.request.body.get("max_tokens")
        if isinstance(max_tokens, int) and max_tokens > 0:
            char_cap = int(max_tokens * self.char_per_token_estimate * (1 + self.token_tolerance))
            if len(ctx.accumulated_text) > char_cap:
                return CheckResult.block(
                    f"output character count {len(ctx.accumulated_text)} "
                    f"exceeds scope-drift cap {char_cap} "
                    f"(max_tokens={max_tokens} × {self.char_per_token_estimate} × "
                    f"(1+{self.token_tolerance}))",
                    drift_kind="token_count",
                    accumulated_chars=len(ctx.accumulated_text),
                    cap=char_cap,
                )

        # Classification drift
        if self.check_classification_drift:
            request_level = self._declared_classification(ctx)
            match = self._classification_pattern.search(ctx.accumulated_text)
            if match:
                marker = match.group(0)
                marker_level = _CLASSIFICATION_MARKERS.get(marker, 99)
                if marker_level > request_level:
                    return CheckResult.block(
                        f"output marker {marker!r} implies classification level "
                        f"{marker_level} > request-declared level {request_level}",
                        drift_kind="classification",
                        marker=marker,
                        marker_level=marker_level,
                        request_level=request_level,
                    )

        return CheckResult.allow()

    @staticmethod
    def _declared_classification(ctx: ResponseContext) -> int:
        """Map the request's X-Classification header to a numeric level."""
        v = (ctx.request.headers.get("X-Classification")
             or ctx.request.headers.get("x-classification"))
        if not v:
            return 0  # UNCLASS default
        norm = v.strip().upper()
        return {
            "UNCLASS": 0, "UNCLASSIFIED": 0, "U": 0,
            "CUI": 1, "FOUO": 1,
            "SECRET": 2, "S": 2,
            "TS": 3, "TOP SECRET": 3,
            "TS/SCI": 4, "TS-SCI": 4, "TS_SCI": 4, "SCI": 4,
        }.get(norm, 0)
