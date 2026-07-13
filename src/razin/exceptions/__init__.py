"""Shared exception hierarchy for Razin."""

from __future__ import annotations

from .base import RazinError
from .config import ConfigError
from .dsl import DslCompileError, DslError, DslRuntimeError, DslSchemaError
from .parsing import SkillParseError
from .sandbox import SandboxBackendError, SandboxError, SandboxValidationError

__all__ = [
    "ConfigError",
    "DslCompileError",
    "DslError",
    "DslRuntimeError",
    "DslSchemaError",
    "RazinError",
    "SandboxBackendError",
    "SandboxError",
    "SandboxValidationError",
    "SkillParseError",
]
