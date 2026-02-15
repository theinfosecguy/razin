"""Re-export shim — canonical definitions live in razin.exceptions.dsl."""

from __future__ import annotations

from razin.exceptions.dsl import DslCompileError, DslError, DslRuntimeError, DslSchemaError

__all__ = ["DslCompileError", "DslError", "DslRuntimeError", "DslSchemaError"]
