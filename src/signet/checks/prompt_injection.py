"""PromptInjectionCheck — pattern + heuristic scan for prompt-injection attempts.

This is intentionally a *coarse* defense. It catches the most common
attack patterns — "ignore previous instructions", "you are now DAN",
embedded system-role spoofs, mask-character injection — but it cannot
detect sophisticated attacks. For richer defense, layer an LLM-judge
plugin on top (TribunalCheck-style) at the COMMITMENT stage.

What the built-in patterns cover:

1. **Override patterns**: "ignore (previous|all|prior) (instructions|rules)",
   "disregard (the|previous|above)", "forget (everything|your prompt)".
2. **Role spoofing**: explicit `system:`, `assistant:`, `user:` markers
   inside what should be user content; embedded `<|im_start|>` /
   `<|system|>` chat-template tokens.
3. **Persona attacks**: "you are now (DAN|jailbroken|in developer mode)",
   "act as if you have no restrictions".
4. **Encoding tricks**: base64 blobs longer than ``base64_min_length``
   that decode to text containing override patterns; zero-width and
   bidirectional Unicode characters.

Each rule has a severity. Default behavior:

* HIGH severity matches → block.
* MEDIUM severity matches → escalate (record + flag, don't auto-block;
  let a downstream judge decide).
* LOW severity matches → audit-only allow with metadata.

Tunable via ``severity_actions``.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.stage import Stage


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    severity: Severity


def _r(name: str, regex: str, severity: Severity, *, flags: int = re.IGNORECASE) -> _Rule:
    return _Rule(name=name, pattern=re.compile(regex, flags), severity=severity)


_DEFAULT_RULES: tuple[_Rule, ...] = (
    # Override patterns. Permissive interior to catch "ignore all previous
    # instructions", "ignore all of the prior messages", etc., where one or
    # more qualifier words sit between the verb and the noun.
    _r(
        "ignore_previous",
        r"\bignore\b[^.!?\n]{0,80}?\b(?:instructions?|prompts?|rules?|messages?|"
        r"(?:system\s+)?prompt|directives?)\b",
        Severity.HIGH,
    ),
    _r("disregard", r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior|all)\b", Severity.HIGH),
    _r(
        "forget_prompt",
        r"\bforget\s+(?:everything|your\s+(?:prompt|instructions|training))\b",
        Severity.HIGH,
    ),
    # Role spoofing inside user content
    _r("inline_system_role", r"<\|(?:im_start|system|im_sep)\|>", Severity.HIGH),
    _r(
        "inline_role_marker",
        r"^\s*(?:system|assistant)\s*:\s*",
        Severity.MEDIUM,
        flags=re.MULTILINE | re.IGNORECASE,
    ),
    # Persona attacks
    _r(
        "dan_jailbreak",
        r"\b(?:DAN|do\s+anything\s+now|jailbroken|jailbreak\s+mode)\b",
        Severity.HIGH,
    ),
    _r(
        "developer_mode",
        r"\b(?:developer|god|admin|root)\s+mode\s+(?:enabled|on|activated)\b",
        Severity.HIGH,
    ),
    _r(
        "no_restrictions",
        r"\b(?:act|behave|respond)\s+as\s+if\s+you\s+have\s+no\s+"
        r"(?:restrictions|limits|filters|rules)\b",
        Severity.HIGH,
    ),
    # Unicode tricks
    _r("zero_width", r"[​-‏‪-‮⁠-⁤﻿]", Severity.MEDIUM),
    _r("bidi_override", r"[‪-‮⁦-⁩]", Severity.HIGH),
)


@dataclass
class PromptInjectionCheck(Check):
    """Coarse pattern + heuristic scan for prompt injection.

    Args:
        severity_actions: Map of :class:`Severity` to action string. Valid
            actions are ``"block"``, ``"escalate"``, and ``"allow"``
            (audit-only). Defaults: HIGH→block, MEDIUM→escalate, LOW→allow.
        base64_min_length: Minimum length of a base64-looking blob to
            attempt decoding. Shorter blobs are too noisy to be worth
            scanning. Defaults to 64.
        scan_decoded_base64: If ``True``, decoded base64 strings are
            re-scanned with the same rules. Catches the trivial
            "base64-encode my injection" trick.
    """

    name = "prompt_injection"
    stage = Stage.ADMISSION

    severity_actions: dict[Severity, str] = field(
        default_factory=lambda: {
            Severity.HIGH: "block",
            Severity.MEDIUM: "escalate",
            Severity.LOW: "allow",
        }
    )
    base64_min_length: int = 64
    scan_decoded_base64: bool = True

    def __post_init__(self) -> None:
        for sev, action in self.severity_actions.items():
            if action not in ("block", "escalate", "allow"):
                raise ValueError(
                    f"severity action for {sev.value!r} must be block|escalate|allow, "
                    f"got {action!r}"
                )

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        text = self._extract_text(ctx.body)
        if not text:
            return CheckResult.allow()

        matches = self._scan(text)
        if self.scan_decoded_base64:
            for decoded in self._extract_base64_decoded(text):
                matches.extend(self._scan(decoded, source="base64"))

        if not matches:
            return CheckResult.allow()

        # Pick the highest-severity match (block > escalate > allow ordering)
        worst = max(matches, key=lambda m: -list(Severity).index(m["severity"]))
        action = self.severity_actions[worst["severity"]]

        meta = {
            "rule": worst["rule"],
            "severity": worst["severity"].value,
            "match_count": len(matches),
            "all_rules_hit": sorted({m["rule"] for m in matches}),
        }
        if "source" in worst:
            meta["match_source"] = worst["source"]

        if action == "block":
            return CheckResult.block(
                f"prompt-injection rule {worst['rule']!r} fired ({worst['severity'].value})",
                **meta,
            )
        if action == "escalate":
            return CheckResult.escalate(
                f"prompt-injection rule {worst['rule']!r} fired ({worst['severity'].value})",
                **meta,
            )
        return CheckResult.allow(
            f"prompt-injection rule {worst['rule']!r} matched but action=allow",
            **meta,
        )

    def _scan(self, text: str, *, source: str = "input") -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rule in _DEFAULT_RULES:
            if rule.pattern.search(text):
                hit = {"rule": rule.name, "severity": rule.severity}
                if source != "input":
                    hit["source"] = source
                out.append(hit)
        return out

    def _extract_base64_decoded(self, text: str) -> list[str]:
        """Pull plausible base64 blobs from text and try to decode them."""
        decoded: list[str] = []
        pattern = rf"[A-Za-z0-9+/]{{{self.base64_min_length},}}={{0,2}}"
        for match in re.finditer(pattern, text):
            blob = match.group(0)
            try:
                raw = base64.b64decode(blob, validate=True)
                decoded.append(raw.decode("utf-8", errors="ignore"))
            except (binascii.Error, ValueError):
                continue
        return decoded

    @staticmethod
    def _extract_text(body: dict[str, Any]) -> str:
        parts: list[str] = []
        for msg in body.get("messages", ()):
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        parts.append(str(part.get("text", "")))
        return "\n".join(parts)
