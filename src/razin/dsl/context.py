"""Immutable evaluation context passed through DSL rule execution."""

from __future__ import annotations

from dataclasses import dataclass

from razin.config import RazinConfig
from razin.model import ParsedSkillDocument


@dataclass(frozen=True)
class EvalContext:
    """Immutable context for a single rule evaluation against one skill."""

    skill_name: str
    parsed: ParsedSkillDocument
    config: RazinConfig
