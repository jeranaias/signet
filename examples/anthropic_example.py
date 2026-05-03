"""Anthropic SDK example.

Prerequisites:

    pip install signet-sign[anthropic]
    # signet must be serving against an Anthropic-OpenAI translator upstream
    signet serve --upstream http://my-litellm:4000/v1 --port 8443

Then:

    ANTHROPIC_API_KEY=sk-ant-... python examples/anthropic_example.py
"""

from __future__ import annotations

import os

from anthropic import Anthropic

from signet.adapters.anthropic import wrap_anthropic


def main() -> None:
    client = wrap_anthropic(
        Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", "no-key")),
        signet_url="http://localhost:8443/v1",
        owner="human:demo@example.com",
    )

    resp = client.messages.create(
        model="claude-3-5-sonnet-latest",
        max_tokens=20,
        messages=[{"role": "user", "content": "Reply with the single word: pong."}],
    )
    print("response:", resp.content[0].text)


if __name__ == "__main__":
    main()
