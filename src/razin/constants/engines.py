"""Engine identifiers for Raisin runtime."""

from __future__ import annotations

ENGINE_DSL: str = "dsl"

CLI_ENGINE_CHOICES: tuple[str, ...] = (ENGINE_DSL,)

REMOVED_ENGINE_CHOICES: tuple[str, ...] = ("default", "legacy", "optionc")
