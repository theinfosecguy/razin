"""Backward-compatible markdown parser module for SKILL.md files."""

from __future__ import annotations

from .skill_markdown import parse_skill_markdown_file

__all__ = ["parse_skill_markdown_file"]
