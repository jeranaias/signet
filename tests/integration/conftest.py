"""Shared fixtures for integration tests.

Integration tests hit live LLM endpoints — local Ollama, remote RigRun,
or anything else OpenAI-compatible. They're slow and require external
state, so they're marked ``@pytest.mark.integration`` and skipped in
default CI runs (the workflow uses ``-m "not integration"``).

Run them locally with::

    pytest -m integration

Skips automatically when the target endpoint isn't reachable, so the
absence of (e.g.) Ollama doesn't fail the suite — it just runs fewer
tests.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest


def _endpoint_reachable(url: str, timeout: float = 2.0) -> bool:
    """Quick TCP probe — does the target accept a connection?"""
    try:
        # Try /v1/models first (OpenAI-shape), fall back to root
        for suffix in ("/models", ""):
            try:
                resp = httpx.get(url.rstrip("/") + suffix, timeout=timeout)
                if resp.status_code < 500:
                    return True
            except httpx.HTTPError:
                continue
    except Exception:
        return False
    return False


@pytest.fixture(scope="session")
def ollama_url() -> str:
    """Local Ollama OpenAI-compatible URL.

    Override via ``SIGNET_TEST_OLLAMA_URL``. Defaults to localhost:11434/v1.
    """
    return os.environ.get("SIGNET_TEST_OLLAMA_URL", "http://localhost:11434/v1")


@pytest.fixture(scope="session")
def ollama_model() -> str:
    """Ollama model tag to test against. Override via SIGNET_TEST_OLLAMA_MODEL.

    Default is ``gemma4:e2b`` — fastest of the local Gemma 4 variants.
    """
    return os.environ.get("SIGNET_TEST_OLLAMA_MODEL", "gemma4:e2b")


@pytest.fixture(scope="session")
def rigrun_url() -> str | None:
    """RigRun proxy URL via Tailscale. Skips tests when unset.

    Set ``SIGNET_TEST_RIGRUN_URL`` to the classification-proxy endpoint,
    e.g. ``https://sn4622129582.tail5bcfa2.ts.net:6443/v1``.
    """
    return os.environ.get("SIGNET_TEST_RIGRUN_URL")


@pytest.fixture(scope="session")
def rigrun_model() -> str:
    return os.environ.get("SIGNET_TEST_RIGRUN_MODEL", "gemma4-26b")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-mark every test in tests/integration/ with the integration marker."""
    for item in items:
        if "tests/integration" in str(item.fspath) or "tests\\integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


@pytest.fixture
def skip_if_no_ollama(ollama_url: str) -> Iterator[None]:
    if not _endpoint_reachable(ollama_url):
        pytest.skip(f"Ollama not reachable at {ollama_url}; skipping")
    yield


@pytest.fixture
def skip_if_no_rigrun(rigrun_url: str | None) -> Iterator[None]:
    if not rigrun_url:
        pytest.skip("SIGNET_TEST_RIGRUN_URL not set; skipping")
    if not _endpoint_reachable(rigrun_url):
        pytest.skip(f"RigRun not reachable at {rigrun_url}; skipping")
    yield
