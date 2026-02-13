"""Scanner orchestration package."""

from __future__ import annotations

from typing import Any

__all__ = ["scan_workspace"]


def __getattr__(name: str) -> Any:
    """Lazily expose scanner APIs to avoid import cycles at package import time."""
    if name == "scan_workspace":
        from .orchestrator import scan_workspace

        return scan_workspace
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
