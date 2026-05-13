"""Tests for SDK adapters.

These exercise the wrapper-mutation logic without importing the real
openai/anthropic packages. We hand the wrappers a dummy object that
quacks like the SDK clients (mutable ``base_url`` and
``default_headers`` attributes) and assert the wrapper sets them
correctly. Real-SDK integration is in ``tests/integration/``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

import pytest

from signet.adapters.anthropic import wrap_anthropic
from signet.adapters.langchain import SignetCallbackHandler
from signet.adapters.openai import wrap_openai


@dataclass
class _DummyClient:
    """Stand-in for openai.OpenAI / anthropic.Anthropic shape."""

    base_url: str = "https://api.example.com/v1"
    default_headers: dict[str, str] = field(default_factory=dict)


class TestWrapOpenAI:
    def test_sets_base_url_and_owner_header(self) -> None:
        client = _DummyClient()
        wrap_openai(client, signet_url="http://signet:8443/v1", owner="human:alice")
        assert client.base_url == "http://signet:8443/v1"
        assert client.default_headers["X-Commit-Owner"] == "human:alice"

    def test_agent_id_header(self) -> None:
        client = _DummyClient()
        wrap_openai(client, signet_url="http://x", agent_id="bot")
        assert client.default_headers["X-Agent-Id"] == "bot"

    def test_policy_with_classification(self) -> None:
        client = _DummyClient()
        wrap_openai(
            client,
            signet_url="http://x",
            policy="acme.v3",
            classification="SECRET",
            clearance="TS",
        )
        assert client.default_headers["X-Policy-Name"] == "acme.v3"
        assert client.default_headers["X-Classification"] == "SECRET"
        assert client.default_headers["X-Caller-Clearance"] == "TS"

    def test_session_id_header(self) -> None:
        client = _DummyClient()
        wrap_openai(client, signet_url="http://x", owner="human:alice", session_id="sess-1")
        assert client.default_headers["X-Signet-Session"] == "sess-1"

    def test_no_owner_or_agent_or_policy_raises(self) -> None:
        client = _DummyClient()
        with pytest.raises(ValueError, match="signet refuses requests"):
            wrap_openai(client, signet_url="http://x")

    def test_returns_same_instance(self) -> None:
        client = _DummyClient()
        out = wrap_openai(client, signet_url="http://x", owner="human:alice")
        assert out is client


class TestWrapAnthropic:
    def test_sets_base_url_and_owner(self) -> None:
        client = _DummyClient()
        wrap_anthropic(client, signet_url="http://signet:8443/v1", owner="human:alice")
        assert client.base_url == "http://signet:8443/v1"
        assert client.default_headers["X-Commit-Owner"] == "human:alice"

    def test_no_owner_raises(self) -> None:
        client = _DummyClient()
        with pytest.raises(ValueError):
            wrap_anthropic(client, signet_url="http://x")


class TestSignetCallbackHandler:
    def test_starts_empty(self) -> None:
        h = SignetCallbackHandler()
        assert h.last_receipt is None
        assert h.last_refusal is None
        assert h.receipts == []

    def test_extracts_receipt_from_response_metadata(self) -> None:
        h = SignetCallbackHandler()

        class FakeResponse:
            response_metadata: ClassVar[dict[str, object]] = {
                "response_headers": {"X-Signet-Receipt": "signet=v1; entry=abc; key=k1; sig=ff"}
            }
            llm_output = None

        from uuid import uuid4

        h.on_llm_end(FakeResponse(), run_id=uuid4())
        assert h.last_receipt == "signet=v1; entry=abc; key=k1; sig=ff"
        assert len(h.receipts) == 1

    def test_extracts_receipt_from_llm_output(self) -> None:
        h = SignetCallbackHandler()

        class FakeResponse:
            llm_output: ClassVar[dict[str, object]] = {
                "response_headers": {"X-Signet-Receipt": "signet=v1; entry=z; key=k1; sig=00"}
            }
            response_metadata = None

        from uuid import uuid4

        h.on_llm_end(FakeResponse(), run_id=uuid4())
        assert h.last_receipt == "signet=v1; entry=z; key=k1; sig=00"

    def test_no_receipt_present(self) -> None:
        h = SignetCallbackHandler()

        class FakeResponse:
            llm_output = None
            response_metadata: ClassVar[dict[str, object]] = {}

        from uuid import uuid4

        h.on_llm_end(FakeResponse(), run_id=uuid4())
        assert h.last_receipt is None

    def test_captures_refusal_payload(self) -> None:
        h = SignetCallbackHandler()

        class FakeBody:
            @staticmethod
            def json() -> dict[str, object]:
                return {
                    "error": "signet refused this request",
                    "reason": "no commit owner",
                }

        class FakeError(Exception):
            body = FakeBody()

        from uuid import uuid4

        h.on_llm_error(FakeError(), run_id=uuid4())
        assert h.last_refusal is not None
        assert h.last_refusal["reason"] == "no commit owner"


class TestOwnerPrefixWarning:
    """v0.1.7 L2: warn (don't reject) when ``owner`` lacks a known
    attribution prefix.

    Audit chain still records whatever the caller passed; the warning
    catches misconfiguration at wrap time so dev consoles surface it
    before production traffic flows.
    """

    def test_unprefixed_owner_warns_openai(self) -> None:
        client = _DummyClient()
        with pytest.warns(UserWarning, match="known prefix"):
            wrap_openai(client, signet_url="http://x", owner="alice@example.com")
        # The wrap still succeeds — it's a warning, not an error —
        # so the audit chain receives whatever was passed.
        assert client.default_headers["X-Commit-Owner"] == "alice@example.com"

    def test_human_prefix_no_warning_openai(self) -> None:
        import warnings

        client = _DummyClient()
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # raise on any warning
            wrap_openai(client, signet_url="http://x", owner="human:alice@example.com")

    def test_agent_prefix_no_warning_openai(self) -> None:
        import warnings

        client = _DummyClient()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            wrap_openai(client, signet_url="http://x", owner="agent:bot-7")

    def test_policy_prefix_no_warning_openai(self) -> None:
        import warnings

        client = _DummyClient()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            wrap_openai(client, signet_url="http://x", owner="policy:acme.v3")

    def test_no_owner_no_warning_openai(self) -> None:
        """When ``owner`` is None (caller used ``agent_id`` / ``policy``
        instead), no warning fires — the soft validator only triggers
        on a present-but-unprefixed owner."""
        import warnings

        client = _DummyClient()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            wrap_openai(client, signet_url="http://x", agent_id="bot")

    def test_unprefixed_owner_warns_anthropic(self) -> None:
        client = _DummyClient()
        with pytest.warns(UserWarning, match="known prefix"):
            wrap_anthropic(client, signet_url="http://x", owner="bob")
        # Still set the header — soft warn, not a hard reject.
        assert client.default_headers["X-Commit-Owner"] == "bob"

    def test_human_prefix_no_warning_anthropic(self) -> None:
        import warnings

        client = _DummyClient()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            wrap_anthropic(client, signet_url="http://x", owner="human:bob@example.com")

    def test_warning_message_suggests_fix(self) -> None:
        client = _DummyClient()
        with pytest.warns(UserWarning) as record:
            wrap_openai(client, signet_url="http://x", owner="raw-string")
        # The warning text mentions a suggested form so callers can
        # self-correct without consulting the docs.
        msg = str(record[0].message)
        assert "human:" in msg
        assert "agent:" in msg
