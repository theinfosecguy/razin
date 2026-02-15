"""Shared helpers for detector tests."""

from __future__ import annotations

from pathlib import Path


def _skill_file(tmp_path: Path, content: str) -> Path:
    """Write a SKILL.md file and return its path."""
    f = tmp_path / "SKILL.md"
    f.write_text(content, encoding="utf-8")
    return f
