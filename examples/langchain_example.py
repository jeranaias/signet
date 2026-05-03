"""LangChain example with signet callback observer.

Prerequisites:

    pip install signet-sign[langchain] langchain-openai
    signet serve --upstream https://api.openai.com/v1 --port 8443
"""

from __future__ import annotations

import os

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

from signet.adapters.langchain import SignetCallbackHandler


def main() -> None:
    handler = SignetCallbackHandler()

    llm = ChatOpenAI(
        model="gpt-4o-mini",
        base_url="http://localhost:8443/v1",
        api_key=os.environ.get("OPENAI_API_KEY", "no-key"),
        default_headers={"X-Commit-Owner": "human:demo@example.com"},
        callbacks=[handler],
    )

    response = llm.invoke([HumanMessage(content="Reply with the single word: pong.")])
    print("response:", response.content)
    print("receipt: ", handler.last_receipt)


if __name__ == "__main__":
    main()
