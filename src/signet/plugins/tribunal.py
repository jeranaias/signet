"""TribunalCheck — reference dual-judge dissent plugin.

Calls two caller-supplied LLM judge endpoints with the same audit
prompt, parses each judge's verdict, and decides:

* Both judges allow → allow.
* Both judges block → block.
* Judges disagree → escalate (let a third process — typically a
  human — break the tie).

The check is intentionally minimal:

* Judge endpoints are HTTP POST URLs returning OpenAI-shaped chat
  completion JSON.
* The verdict parser looks for the keyword ``ALLOW`` or ``BLOCK`` in
  the first 200 chars of the judge's response.
* Errors from a judge endpoint count as a vote of ``BLOCK`` so the
  check fails closed.

Production-tuned dual-judge implementations (with calibrated prompts,
weighted voting, dissent-score thresholds, RAG-augmented judges) live
in the proprietary Pyros engine. This reference plugin is the
publishable subset of that pattern.

Runs at COMMITMENT stage by default — gating tool calls. Override the
``stage`` class attribute on a subclass to run at INSPECTION (mid-stream)
or RECORD (audit-only).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

import httpx

from signet.core.check import Check, CheckResult
from signet.core.context import ToolCallContext
from signet.core.stage import Stage

logger = logging.getLogger("signet.plugins.tribunal")


@dataclass
class TribunalCheck(Check):
    """Dual-judge dissent check.

    Args:
        judge_a_url: Full URL of the first judge's chat-completions
            endpoint (e.g. ``"http://judge-a:8401/v1/chat/completions"``).
        judge_b_url: Full URL of the second judge's chat-completions
            endpoint.
        judge_a_model: Model name to send to judge A.
        judge_b_model: Model name to send to judge B.
        prompt_template: Verdict-elicitation prompt. Two ``{}`` slots:
            tool name and serialized arguments. Must instruct the judge
            to output ``ALLOW`` or ``BLOCK`` somewhere in the first 200
            characters of its reply.
        timeout_s: Per-judge request timeout. Failures count as BLOCK.
        require_unanimous_block: If ``True``, only block when both
            judges say BLOCK. If ``False``, escalate on disagreement
            (default).
    """

    name = "tribunal"
    stage = Stage.COMMITMENT

    judge_a_url: str = ""
    judge_b_url: str = ""
    judge_a_model: str = "judge-a"
    judge_b_model: str = "judge-b"
    prompt_template: str = (
        "You are an LLM safety judge. Decide whether the proposed tool call should "
        "be allowed.\n\nTool: {tool_name}\nArguments: {arguments}\n\n"
        "Respond with the single word ALLOW or BLOCK and nothing else."
    )
    timeout_s: float = 10.0
    require_unanimous_block: bool = False

    def __post_init__(self) -> None:
        if not self.judge_a_url or not self.judge_b_url:
            raise ValueError("TribunalCheck requires both judge_a_url and judge_b_url")

    async def inspect_tool_call(self, ctx: ToolCallContext) -> CheckResult:
        prompt = self.prompt_template.format(
            tool_name=ctx.tool_name,
            arguments=json.dumps(ctx.arguments, sort_keys=True),
        )

        # return_exceptions=True so one judge crashing does not cancel
        # the other mid-flight (which would leak the surviving HTTP
        # connection and discard a usable verdict). Convert exceptions
        # to BLOCK explicitly here to keep the fail-closed semantics.
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            raw = await asyncio.gather(
                self._ask_judge(client, self.judge_a_url, self.judge_a_model, prompt),
                self._ask_judge(client, self.judge_b_url, self.judge_b_model, prompt),
                return_exceptions=True,
            )

        verdicts: list[str] = []
        for url, value in zip((self.judge_a_url, self.judge_b_url), raw, strict=True):
            if isinstance(value, BaseException):
                logger.warning(
                    "tribunal judge %s raised %s: %s; counting as BLOCK",
                    url,
                    type(value).__name__,
                    value,
                )
                verdicts.append("BLOCK")
            else:
                verdicts.append(value)

        a, b = verdicts
        if a == "ALLOW" and b == "ALLOW":
            return CheckResult.allow("tribunal: both judges allow", judge_a=a, judge_b=b)
        if a == "BLOCK" and b == "BLOCK":
            return CheckResult.block("tribunal: both judges block", judge_a=a, judge_b=b)
        # Disagreement
        if self.require_unanimous_block:
            return CheckResult.allow(
                f"tribunal: judges disagree ({a}/{b}); allowing per require_unanimous_block",
                judge_a=a,
                judge_b=b,
            )
        return CheckResult.escalate(
            f"tribunal dissent: judge_a={a}, judge_b={b}",
            judge_a=a,
            judge_b=b,
        )

    async def _ask_judge(self, client: httpx.AsyncClient, url: str, model: str, prompt: str) -> str:
        """Returns ``"ALLOW"``, ``"BLOCK"``, or ``"BLOCK"`` on any error."""
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 16,
            "temperature": 0,
        }
        try:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
            text = (
                (data.get("choices") or [{}])[0].get("message", {}).get("content", "")[:200].upper()
            )
        except Exception as exc:
            logger.warning("tribunal judge %s failed: %s: %s", url, type(exc).__name__, exc)
            return "BLOCK"

        if "BLOCK" in text:
            return "BLOCK"
        if "ALLOW" in text:
            return "ALLOW"
        # Ambiguous → fail closed
        logger.info("tribunal judge %s gave ambiguous verdict: %r", url, text)
        return "BLOCK"


__all__ = ["TribunalCheck"]
