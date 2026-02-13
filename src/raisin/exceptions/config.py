"""Configuration-related exceptions."""

from __future__ import annotations

from raisin.exceptions.base import RaisinError


class ConfigError(RaisinError, ValueError):
    """Raised when scanner configuration is invalid."""
