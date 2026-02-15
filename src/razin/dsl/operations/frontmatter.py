"""Frontmatter inspection operation for DSL rules."""

from __future__ import annotations

from typing import Any

from razin.dsl.operations.shared import (
    first_field_with_keyword,
    is_empty_value,
    resolve_frontmatter_path,
)
from razin.model import FindingCandidate
from razin.types.dsl import EvalContext


def run_frontmatter_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Inspect frontmatter structure for specific keys/values."""
    fm_path: str = match_config.get("path", "")
    empty_check: bool = match_config.get("empty_check", True)

    if not isinstance(ctx.parsed.frontmatter, dict):
        return []

    value = resolve_frontmatter_path(ctx.parsed.frontmatter, fm_path)
    if value is None:
        return []

    if empty_check and is_empty_value(value):
        return []

    evidence = first_field_with_keyword(ctx.parsed, fm_path.split(".")[-1])
    return [
        FindingCandidate(
            rule_id="",
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", ""),
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
    ]
