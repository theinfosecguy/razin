"""Configuration-related exceptions."""

from __future__ import annotations

from razin.exceptions.base import RaisinError


class ConfigError(RaisinError, ValueError):
    """Raised when scanner configuration is invalid."""
