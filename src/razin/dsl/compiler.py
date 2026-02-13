"""Compiler: transform validated YAML AST into a typed execution plan."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from razin.dsl.errors import DslCompileError
from razin.dsl.ops import OP_REGISTRY
from razin.dsl.schema import validate_rule

logger = logging.getLogger(__name__)


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


def compile_rule(data: dict[str, Any], source_path: str) -> CompiledRule:
    """Validate and compile a YAML rule dict into a CompiledRule.

    Raises DslSchemaError on schema violations, DslCompileError on
    compilation failures.
    """
    validate_rule(data, source_path)

    strategy_name = data["match"]["strategy"]
    if strategy_name not in OP_REGISTRY:
        raise DslCompileError(f"{source_path}: strategy '{strategy_name}' not found in op registry")

    return CompiledRule(
        source_path=source_path,
        rule_id=data["rule_id"],
        public_rule_id=data.get("public_rule_id", data["rule_id"]),
        version=data["version"],
        strategy_name=strategy_name,
        match_config=dict(data["match"]),
        metadata=dict(data["metadata"]),
        base_score=data["scoring"]["base_score"],
        dedupe=data.get("dedupe", True),
        profiles=dict(data.get("profiles", {})),
    )


def compile_rules(
    rules_data: list[tuple[str, dict[str, Any]]],
) -> list[CompiledRule]:
    """Compile multiple rule dicts. Fail-fast on any error."""
    compiled: list[CompiledRule] = []
    for source_path, data in rules_data:
        compiled.append(compile_rule(data, source_path))
    return compiled
