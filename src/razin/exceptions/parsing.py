"""Parsing-related exceptions."""

from __future__ import annotations

from razin.exceptions.base import RaisinError


class SkillParseError(RaisinError, ValueError):
    """Raised when a SKILL.md file cannot be parsed."""
