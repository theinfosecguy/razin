"""Shared exception hierarchy for Razin."""

from __future__ import annotations

from .base import RazinError
from .config import ConfigError
from .parsing import SkillParseError

__all__ = ["ConfigError", "RazinError", "SkillParseError"]
