"""Typosquatting detection operation for DSL rules."""

from __future__ import annotations

from typing import Any

from razin.dsl.operations.shared import (
    declared_name,
    format_template,
    levenshtein_distance,
)
from razin.model import Evidence, FindingCandidate
from razin.types.dsl import EvalContext
from razin.utils import normalize_similarity_name, sanitize_output_name


def run_typosquat_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Compare skill name against baseline using edit distance."""
    max_distance: int = match_config.get("max_distance", 2)
    min_name_length: int = match_config.get("min_name_length", 5)
    baseline_source: str = match_config.get("baseline_source", "config.typosquat_baseline")
    desc_tpl = metadata.get("description_template", metadata.get("description", ""))

    if baseline_source == "config.typosquat_baseline":
        baseline = ctx.config.typosquat_baseline
    else:
        baseline = tuple(match_config.get("baseline", []))

    if not baseline:
        return []

    self_names: set[str] = set()
    self_names.add(normalize_similarity_name(ctx.skill_name))
    decl = declared_name(ctx.parsed)
    if decl:
        self_names.add(normalize_similarity_name(decl))
    folder_name = sanitize_output_name(ctx.parsed.file_path.parent.name)
    if folder_name:
        self_names.add(normalize_similarity_name(folder_name))

    names_to_check = [ctx.skill_name]
    if decl:
        names_to_check.append(decl)

    for candidate_name in names_to_check:
        normalized = normalize_similarity_name(candidate_name)
        for base in baseline:
            base_norm = normalize_similarity_name(base)
            if base_norm in self_names:
                continue
            dist = levenshtein_distance(normalized, base_norm)
            too_close = dist <= max_distance
            long_enough = min(len(normalized), len(base_norm)) >= min_name_length
            if too_close and long_enough:
                description = format_template(desc_tpl, name=candidate_name, value=base)
                return [
                    FindingCandidate(
                        rule_id="",
                        score=base_score,
                        confidence=metadata["confidence"],
                        title=metadata["title"],
                        description=description,
                        evidence=Evidence(
                            path=str(ctx.parsed.file_path),
                            line=1,
                            snippet=(ctx.parsed.raw_text.splitlines()[0][:200] if ctx.parsed.raw_text else ""),
                        ),
                        recommendation=metadata["recommendation"],
                    )
                ]

    return []
