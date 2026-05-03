"""SDK adapters — drop-in wrappers around popular LLM client libraries.

Three adapters ship in v0.1:

* :func:`signet.adapters.openai.wrap_openai` — wraps an
  ``openai.OpenAI`` or ``openai.AsyncOpenAI`` client to point at a
  signet proxy and inject owner / classification headers.
* :func:`signet.adapters.anthropic.wrap_anthropic` — same shape for
  ``anthropic.Anthropic`` and ``anthropic.AsyncAnthropic``.
* :class:`signet.adapters.langchain.SignetCallbackHandler` — a
  LangChain callback that surfaces signet receipts and refusal
  reasons to LangChain's tracing.

Each adapter is *opt-in*: pip-extras ``signet-sign[openai]``,
``signet-sign[anthropic]``, ``signet-sign[langchain]`` install the
required client library. The bare install does not pull them in.

Adapters do not change the way the underlying SDK works — same method
names, same async/sync semantics, same return types. They only:

1. Rewrite the ``base_url`` to point at the signet proxy.
2. Inject ``X-Commit-Owner`` (or ``X-Agent-Id``, ``X-Policy-Name``)
   into every request from a value provided once at wrap time.
3. Optionally inject ``X-Classification`` and ``X-Caller-Clearance``.
4. Expose the ``X-Signet-Receipt`` response header on a
   ``last_receipt`` attribute for caller verification.
"""

from __future__ import annotations

from signet.adapters.anthropic import wrap_anthropic
from signet.adapters.langchain import SignetCallbackHandler
from signet.adapters.openai import wrap_openai

__all__ = [
    "SignetCallbackHandler",
    "wrap_anthropic",
    "wrap_openai",
]
