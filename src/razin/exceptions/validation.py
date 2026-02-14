"""Structured validation error model for config and rule validation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationError:
    """A single validation error with stable code and location context."""

    code: str
    path: str
    field: str
    message: str
    hint: str = ""
    line: int | None = None
    column: int | None = None

    def format(self) -> str:
        """Format as a human-readable single-line message."""
        location = self.path
        if self.line is not None:
            location = f"{location}:{self.line}"
            if self.column is not None:
                location = f"{location}:{self.column}"
        parts = [f"[{self.code}]", location, self.message]
        if self.hint:
            parts.append(f"({self.hint})")
        return " ".join(parts)


def sort_errors(errors: list[ValidationError]) -> list[ValidationError]:
    """Sort validation errors deterministically by code, path, field."""
    return sorted(errors, key=lambda e: (e.code, e.path, e.field, e.line or 0))


def format_errors(errors: list[ValidationError]) -> str:
    """Format a list of validation errors as a multi-line string."""
    sorted_errs = sort_errors(errors)
    return "\n".join(e.format() for e in sorted_errs)
