"""Shared fixtures for adversarial bypass tests."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/adversarial" in str(item.fspath) or "tests\\adversarial" in str(item.fspath):
            item.add_marker(pytest.mark.adversarial)
