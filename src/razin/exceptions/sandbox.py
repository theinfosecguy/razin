"""Sandbox verification exceptions."""

from __future__ import annotations

from razin.exceptions.base import RazinError


class SandboxError(RazinError):
    """Base class for sandbox verification failures."""


class SandboxValidationError(SandboxError, ValueError):
    """Raised before a backend can be invoked when an artifact is invalid."""


class SandboxBackendError(SandboxError):
    """Raised when an explicitly selected backend cannot complete its work."""
