"""Reporting package for Razin outputs."""

from __future__ import annotations

from typing import Any

__all__ = ["build_summary", "write_skill_reports"]


def __getattr__(name: str) -> Any:
    """Lazily expose reporting APIs to avoid import cycles at package import time."""
    if name in {"build_summary", "write_skill_reports"}:
        from .writer import build_summary, write_skill_reports

        exports = {
            "build_summary": build_summary,
            "write_skill_reports": write_skill_reports,
        }
        return exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
