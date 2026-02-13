"""Shared pytest fixtures for repository-local test data."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixtures_root() -> Path:
    """Return root directory for test fixtures."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def basic_repo_root(fixtures_root: Path) -> Path:
    """Return the primary fixture repository path."""
    return fixtures_root / "repos" / "basic"
