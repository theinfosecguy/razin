"""Parsing-related exceptions."""

from __future__ import annotations

from raisin.exceptions.base import RaisinError


class SkillParseError(RaisinError, ValueError):
    """Raised when a SKILL.md file cannot be parsed."""
