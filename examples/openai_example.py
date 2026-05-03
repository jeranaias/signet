"""Drop-in OpenAI SDK example.

Prerequisites:

    pip install signet-sign[openai]
    signet serve --upstream https://api.openai.com/v1 --port 8443  # in another terminal

Then:

    OPENAI_API_KEY=sk-... python examples/openai_example.py
"""

from __future__ import annotations

import os

from openai import OpenAI

from signet.adapters.openai import wrap_openai


def main() -> None:
    client = wrap_openai(
        OpenAI(api_key=os.environ.get("OPENAI_API_KEY", "no-key-needed-for-local")),
        signet_url="http://localhost:8443/v1",
        owner="human:demo@example.com",
        classification="UNCLASS",
        clearance="UNCLASS",
    )

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Reply with the single word: pong."}],
        max_tokens=20,
    )

    print("response:", resp.choices[0].message.content)
    # The signet receipt sits on the raw HTTP response; the OpenAI SDK
    # exposes it via the `with_raw_response` accessor:
    raw = client.chat.completions.with_raw_response.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "ping"}],
        max_tokens=5,
    )
    receipt = raw.headers.get("X-Signet-Receipt")
    print("receipt:", receipt)


if __name__ == "__main__":
    main()
