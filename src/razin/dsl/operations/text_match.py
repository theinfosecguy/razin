"""Text matching operations for DSL rules (keys, fields, hints, keywords)."""

from __future__ import annotations

import re
from typing import Any

from razin.constants.detectors import (
    ENV_REF_PATTERN,
    NON_SECRET_ENV_OPERATORS,
    SECRET_ENV_KEYWORDS,
    SECRET_PLACEHOLDER_VALUE_PATTERN,
)
from razin.detectors.common import dedupe_candidates, field_evidence
from razin.dsl.operations.shared import (
    best_evidence_for_hint,
    first_field_with_keyword,
    format_template,
    hint_is_negated,
)
from razin.model import Evidence, FindingCandidate
from razin.types.dsl import EvalContext


def run_key_pattern_match(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan document keys for keyword matches."""
    keywords: list[str] = match_config.get("keywords", [])
    match_mode: str = match_config.get("match_mode", "contains")
    skip_placeholder_values: bool = match_config.get("skip_placeholder_values", False)
    skip_placeholder_values_anywhere: bool = match_config.get("skip_placeholder_values_anywhere", False)
    desc_tpl = metadata.get("description_template", metadata.get("description", ""))
    keyword_set = frozenset(keywords)
    fields_by_line = {field.line: field for field in ctx.parsed.fields}

    findings: list[FindingCandidate] = []
    for key in ctx.parsed.keys:
        normalized_key = key.key.lower()
        matched = False
        if match_mode == "exact":
            matched = normalized_key in keyword_set
        else:
            matched = any(kw in normalized_key for kw in keywords)

        if matched:
            field = fields_by_line.get(key.line)
            if (
                skip_placeholder_values
                and field is not None
                and _is_placeholder_secret_value(field.value)
                and (field.in_code_block or skip_placeholder_values_anywhere)
            ):
                continue
            description = format_template(desc_tpl, key=key.key)
            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=description,
                    evidence=Evidence(
                        path=str(ctx.parsed.file_path),
                        line=key.line,
                        snippet=key.snippet,
                    ),
                    recommendation=metadata["recommendation"],
                )
            )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_field_pattern_match(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan field values with a regex pattern."""
    pattern_str: str = match_config["pattern"]
    exclude_fn_name: str | None = match_config.get("exclude_pattern_fn")
    compiled = re.compile(pattern_str, re.IGNORECASE)
    exclude_fn = _EXCLUDE_FUNCTIONS.get(exclude_fn_name) if exclude_fn_name else None

    findings: list[FindingCandidate] = []
    for field in ctx.parsed.fields:
        if not compiled.search(field.value):
            continue
        if exclude_fn and exclude_fn(field.value):
            continue
        findings.append(
            FindingCandidate(
                rule_id="",
                score=base_score,
                confidence=metadata["confidence"],
                title=metadata["title"],
                description=metadata.get("description", ""),
                evidence=field_evidence(ctx.parsed, field),
                recommendation=metadata["recommendation"],
            )
        )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_hint_count(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Count strong/weak hints in raw text with optional negation awareness."""
    strong_hints: list[str] = match_config.get("strong_hints", [])
    weak_hints: list[str] = match_config.get("weak_hints", [])
    min_hint_count: int = match_config.get("min_hint_count", 2)
    require_strong: bool = match_config.get("require_strong", False)
    negation_aware: bool = match_config.get("negation_aware", False)

    lowered = ctx.parsed.raw_text.lower()

    if negation_aware:
        strong_matches = [h for h in strong_hints if h in lowered and not hint_is_negated(lowered, h)]
        weak_matches = [h for h in weak_hints if h in lowered and not hint_is_negated(lowered, h)]
    else:
        strong_matches = [h for h in strong_hints if h in lowered]
        weak_matches = [h for h in weak_hints if h in lowered]

    if require_strong and not strong_matches:
        return []

    all_matches = strong_matches + weak_matches
    if len(all_matches) < min_hint_count:
        return []

    best_hint = strong_matches[0] if strong_matches else all_matches[0]
    evidence = best_evidence_for_hint(ctx.parsed, best_hint)

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


def run_keyword_in_text(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Search raw text for keyword phrases."""
    hints: list[str] = match_config.get("hints", [])
    first_match_only: bool = match_config.get("first_match_only", True)

    lowered = ctx.parsed.raw_text.lower()
    for hint in hints:
        if hint not in lowered:
            continue

        evidence = first_field_with_keyword(ctx.parsed, hint.split()[0])
        finding = FindingCandidate(
            rule_id="",
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", ""),
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
        if first_match_only:
            return [finding]

    return []


def _is_non_secret_env_ref(value: str) -> bool:
    """Return True when env-var references are non-secret operators."""
    for match in ENV_REF_PATTERN.finditer(value):
        ref = match.group(0).lower().strip("${} ")
        if ref in NON_SECRET_ENV_OPERATORS:
            continue
        if any(kw in ref for kw in SECRET_ENV_KEYWORDS):
            return False
    return True


def _is_placeholder_secret_value(value: str) -> bool:
    """Return True for placeholder secret values."""
    return bool(SECRET_PLACEHOLDER_VALUE_PATTERN.search(value))


_EXCLUDE_FUNCTIONS: dict[str, Any] = {
    "is_non_secret_env_ref": _is_non_secret_env_ref,
}
