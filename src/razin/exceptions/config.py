"""Configuration-related exceptions."""

from __future__ import annotations

from razin.exceptions.base import RazinError


class ConfigError(RazinError, ValueError):
    """Raised when scanner configuration is invalid."""
