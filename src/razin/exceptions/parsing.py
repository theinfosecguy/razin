"""Parsing-related exceptions."""

from __future__ import annotations

from razin.exceptions.base import RazinError


class SkillParseError(RazinError, ValueError):
    """Raised when a SKILL.md file cannot be parsed."""
