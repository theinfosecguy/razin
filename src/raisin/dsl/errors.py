"""Typed DSL error hierarchy."""

from __future__ import annotations

from raisin.exceptions.base import RaisinError


class DslError(RaisinError):
    """Base class for DSL-related errors."""


class DslSchemaError(DslError):
    """Raised when a YAML rule file fails schema validation."""


class DslCompileError(DslError):
    """Raised when a validated rule cannot be compiled into an execution plan."""


class DslRuntimeError(DslError):
    """Raised during rule execution for unexpected conditions."""
