"""Frozen dataclasses for the DSL subsystem."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from razin.config import RazinConfig
from razin.model import ParsedSkillDocument


@dataclass(frozen=True)
class EvalContext:
    """Immutable context for a single rule evaluation against one skill."""

    skill_name: str
    parsed: ParsedSkillDocument
    config: RazinConfig


@dataclass(frozen=True)
class CompiledRule:
    """Typed execution plan for a single DSL rule."""

    source_path: str
    rule_id: str
    public_rule_id: str
    version: int
    strategy_name: str
    match_config: dict[str, Any]
    metadata: dict[str, Any]
    base_score: int
    dedupe: bool
    profiles: dict[str, dict[str, Any]]
