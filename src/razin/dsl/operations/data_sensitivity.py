"""Data sensitivity classification operation for DSL rules."""

from __future__ import annotations

from typing import Any

from razin.constants.data_sensitivity import (
    FINANCIAL_KEYWORDS,
    MEDICAL_KEYWORDS,
    PII_KEYWORDS,
    WEAK_MEDIUM_SENSITIVITY_KEYWORDS,
)
from razin.detectors.common import field_evidence
from razin.dsl.operations.shared import keyword_in_text
from razin.model import Evidence, FindingCandidate, ParsedSkillDocument
from razin.types.config import DataSensitivityConfig
from razin.types.dsl import EvalContext


def run_data_sensitivity_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Classify skill by data sensitivity based on explicit text evidence."""
    from razin.constants.data_sensitivity import (
        KEYWORD_BONUS,
        SENSITIVITY_TIER_SCORES,
        SERVICE_CATEGORY_MAP,
    )

    ds_config = ctx.config.data_sensitivity
    custom_categories = ds_config.service_categories or {}
    category_map = {**SERVICE_CATEGORY_MAP, **custom_categories}

    max_keyword_preview = int(match_config.get("max_keyword_preview", 5))
    min_medium_keyword_hits = max(1, int(match_config.get("min_medium_keyword_hits", 1)))
    require_keywords_for_medium_service = bool(match_config.get("require_keywords_for_medium_service", True))

    service_match = _find_service_match(ctx.parsed, ds_config)
    high_keyword_matches = _collect_keyword_matches(ctx.parsed, ds_config.high_keywords)
    medium_keyword_matches = _collect_keyword_matches(ctx.parsed, ds_config.medium_keywords)
    medium_strong_keyword_matches = [
        (keyword, evidence)
        for keyword, evidence in medium_keyword_matches
        if keyword not in WEAK_MEDIUM_SENSITIVITY_KEYWORDS
    ]
    has_keyword_context = bool(high_keyword_matches or medium_strong_keyword_matches)

    if (
        service_match is not None
        and require_keywords_for_medium_service
        and service_match[0] == "medium"
        and not has_keyword_context
    ):
        service_match = None

    if (
        service_match is None
        and not high_keyword_matches
        and len(medium_strong_keyword_matches) < min_medium_keyword_hits
    ):
        return []

    matched_service: str | None = None
    service_tier: str | None = None
    service_evidence: Evidence | None = None
    if service_match is not None:
        service_tier, matched_service, service_evidence = service_match
    else:
        if high_keyword_matches:
            service_tier = "high"
        elif medium_strong_keyword_matches:
            service_tier = "medium"

    assert service_tier is not None
    score = SENSITIVITY_TIER_SCORES.get(service_tier, base_score)

    if high_keyword_matches:
        score = min(score + KEYWORD_BONUS, 100)

    category = "unknown"
    category_source = "keyword"
    if matched_service and matched_service in category_map:
        category = category_map[matched_service]
        category_source = "service"
    elif high_keyword_matches:
        category = _infer_category_from_keywords([keyword for keyword, _ in high_keyword_matches])
    elif medium_keyword_matches:
        category = _infer_category_from_keywords([keyword for keyword, _ in medium_keyword_matches])

    high_keywords = [keyword for keyword, _ in high_keyword_matches]
    medium_keywords = [keyword for keyword, _ in medium_keyword_matches]

    source_components: list[str] = []
    if service_evidence is not None:
        source_components.append("service_text")
    if high_keyword_matches:
        source_components.append("keyword_high")
    if medium_strong_keyword_matches:
        source_components.append("keyword_medium")
    if not source_components:
        return []

    desc_parts: list[str] = []
    if matched_service:
        desc_parts.append(f"Skill text references service '{matched_service}' ({service_tier}-sensitivity service).")
    else:
        desc_parts.append(f"Skill text contains {service_tier}-sensitivity data keywords.")
    desc_parts.append(f"Category: {category} (category_source={category_source}).")
    desc_parts.append(f"signal_source={'+'.join(source_components)}.")

    if high_keywords:
        kw_preview = ", ".join(high_keywords[:max_keyword_preview])
        desc_parts.append(f"High-sensitivity keywords: {kw_preview}.")
    if medium_keywords:
        kw_preview = ", ".join(medium_keywords[:max_keyword_preview])
        desc_parts.append(f"Medium-sensitivity keywords: {kw_preview}.")

    description = " ".join(desc_parts)

    evidence = (
        service_evidence
        or _first_evidence(high_keyword_matches)
        or _first_evidence(medium_strong_keyword_matches)
    )
    if evidence is None:
        return []

    return [
        FindingCandidate(
            rule_id="",
            score=score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=description,
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
    ]


def _find_service_match(
    parsed: ParsedSkillDocument,
    ds_config: DataSensitivityConfig,
) -> tuple[str, str, Evidence] | None:
    """Return the first explicit service mention with its inferred sensitivity tier."""
    tiered_services: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("high", ds_config.high_services),
        ("medium", ds_config.medium_services),
        ("low", ds_config.low_services),
    )
    for tier, services in tiered_services:
        for service in services:
            evidence = _find_keyword_evidence(parsed, service)
            if evidence is not None:
                return tier, service, evidence
    return None


def _collect_keyword_matches(parsed: ParsedSkillDocument, keywords: tuple[str, ...]) -> list[tuple[str, Evidence]]:
    """Collect unique keyword matches along with real-line evidence."""
    matches: list[tuple[str, Evidence]] = []
    seen_keywords: set[str] = set()
    for keyword in keywords:
        normalized = keyword.lower()
        if normalized in seen_keywords:
            continue
        evidence = _find_keyword_evidence(parsed, normalized)
        if evidence is None:
            continue
        seen_keywords.add(normalized)
        matches.append((normalized, evidence))
    return matches


def _find_keyword_evidence(parsed: ParsedSkillDocument, keyword: str) -> Evidence | None:
    """Return evidence for a keyword when it appears in parsed field text."""
    keyword_lower = keyword.lower()
    for field in parsed.fields:
        if keyword_in_text(keyword_lower, field.value.lower()):
            return field_evidence(parsed, field)
    return None


def _first_evidence(matches: list[tuple[str, Evidence]]) -> Evidence | None:
    """Return the first evidence object from keyword match tuples."""
    if not matches:
        return None
    return matches[0][1]


def _infer_category_from_keywords(keywords: list[str]) -> str:
    """Infer a data category from matched sensitivity keywords."""
    for kw in keywords:
        if kw in FINANCIAL_KEYWORDS:
            return "financial"
        if kw in MEDICAL_KEYWORDS:
            return "medical/health"
        if kw in PII_KEYWORDS:
            return "PII"
    return "sensitive-data"
