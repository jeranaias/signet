"""End-to-end tests against RigRun's classification-proxy endpoint.

These tests target the RigRun-hosted classification-proxy at the
``SIGNET_TEST_RIGRUN_URL`` environment variable. They verify that
signet's pipeline composes correctly when forwarding to a real
production-grade upstream that itself enforces classification.

Skipped automatically when SIGNET_TEST_RIGRUN_URL isn't set or the
endpoint isn't reachable.

Run with::

    SIGNET_TEST_RIGRUN_URL=https://sn4622129582.tail5bcfa2.ts.net:6443/v1 \\
        pytest -m integration tests/integration/test_against_rigrun.py
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from signet.checks import OwnerResolutionCheck
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig

pytestmark = pytest.mark.integration


def _build_client(upstream: str, tmp_path: Path) -> TestClient:
    pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True)])
    config = ServerConfig(
        upstream_url=upstream,
        audit_log_path=tmp_path / "audit.jsonl",
        allow_ephemeral_key=True,
    )
    return TestClient(SignetApp(config=config, pipeline=pipeline).app)


class TestRigRunForward:
    def test_round_trip_against_rigrun(
        self,
        rigrun_url: str | None,
        rigrun_model: str,
        skip_if_no_rigrun: None,
        tmp_path: Path,
    ) -> None:
        assert rigrun_url is not None  # narrowed by skip_if_no_rigrun
        client = _build_client(rigrun_url, tmp_path)

        r = client.post(
            "/v1/chat/completions",
            json={
                "model": rigrun_model,
                "messages": [{"role": "user", "content": "Reply with: ok"}],
                "max_tokens": 5,
                "stream": False,
            },
            headers={"X-Commit-Owner": "human:integration-test"},
            timeout=120,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert "choices" in data

    def test_signet_in_front_of_rigrun_emits_receipt(
        self,
        rigrun_url: str | None,
        rigrun_model: str,
        skip_if_no_rigrun: None,
        tmp_path: Path,
    ) -> None:
        """Validates the layered architecture: signet's signed receipt
        fires even when the upstream itself is enforcing policy."""
        assert rigrun_url is not None
        client = _build_client(rigrun_url, tmp_path)

        r = client.post(
            "/v1/chat/completions",
            json={
                "model": rigrun_model,
                "messages": [{"role": "user", "content": "Reply with: ok"}],
                "max_tokens": 5,
                "stream": False,
            },
            headers={"X-Commit-Owner": "human:integration-test"},
            timeout=120,
        )
        assert r.status_code == 200
        receipt = r.headers.get("X-Signet-Receipt") or r.headers.get("x-signet-receipt")
        assert receipt is not None
