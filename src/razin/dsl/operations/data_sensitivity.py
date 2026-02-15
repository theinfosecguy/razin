"""Data sensitivity classification operation for DSL rules."""

from __future__ import annotations

from typing import Any

from razin.constants.data_sensitivity import (
    FINANCIAL_KEYWORDS,
    MEDICAL_KEYWORDS,
    PII_KEYWORDS,
)
from razin.dsl.context import EvalContext
from razin.dsl.operations.shared import (
    declared_name,
    keyword_in_text,
    service_matches_name,
)
from razin.model import Evidence, FindingCandidate


def run_data_sensitivity_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Classify skill by data sensitivity of integrated services."""
    from razin.constants.data_sensitivity import (
        KEYWORD_BONUS,
        SENSITIVITY_TIER_SCORES,
        SERVICE_CATEGORY_MAP,
    )

    ds_config = ctx.config.data_sensitivity
    custom_categories = ds_config.service_categories or {}
    category_map = {**SERVICE_CATEGORY_MAP, **custom_categories}

    skill_name_lower = ctx.skill_name.lower()
    decl = declared_name(ctx.parsed)

    names_to_check = [skill_name_lower]
    if decl:
        names_to_check.append(decl.lower())

    service_tier: str | None = None
    matched_service: str | None = None

    for name in names_to_check:
        for svc in ds_config.high_services:
            if service_matches_name(svc, name):
                service_tier = "high"
                matched_service = svc
                break
        if service_tier:
            break
        for svc in ds_config.medium_services:
            if service_matches_name(svc, name):
                service_tier = "medium"
                matched_service = svc
                break
        if service_tier:
            break
        for svc in ds_config.low_services:
            if service_matches_name(svc, name):
                service_tier = "low"
                matched_service = svc
                break
        if service_tier:
            break

    body_lower = ctx.parsed.raw_text.lower()
    high_kw_matches = [kw for kw in ds_config.high_keywords if keyword_in_text(kw, body_lower)]
    medium_kw_matches = [kw for kw in ds_config.medium_keywords if keyword_in_text(kw, body_lower)]

    if service_tier is None and not high_kw_matches and not medium_kw_matches:
        return []

    if service_tier is None:
        if high_kw_matches:
            service_tier = "high"
        elif medium_kw_matches:
            service_tier = "medium"

    assert service_tier is not None
    score = SENSITIVITY_TIER_SCORES.get(service_tier, base_score)

    if high_kw_matches:
        score = min(score + KEYWORD_BONUS, 100)

    category = "unknown"
    if matched_service and matched_service in category_map:
        category = category_map[matched_service]
    elif high_kw_matches:
        category = _infer_category_from_keywords(high_kw_matches)
    elif medium_kw_matches:
        category = _infer_category_from_keywords(medium_kw_matches)

    desc_parts: list[str] = []
    if matched_service:
        desc_parts.append(f"Skill integrates with {matched_service} ({service_tier}-sensitivity service).")
    else:
        desc_parts.append(f"Skill body contains {service_tier}-sensitivity data keywords.")
    desc_parts.append(f"Category: {category}.")

    if high_kw_matches:
        kw_preview = ", ".join(high_kw_matches[:5])
        desc_parts.append(f"High-sensitivity keywords: {kw_preview}.")
    if medium_kw_matches:
        kw_preview = ", ".join(medium_kw_matches[:5])
        desc_parts.append(f"Medium-sensitivity keywords: {kw_preview}.")

    description = " ".join(desc_parts)

    snippet = f"service={matched_service or 'N/A'}, category={category}, tier={service_tier}"
    evidence = Evidence(
        path=str(ctx.parsed.file_path),
        line=1,
        snippet=snippet[:200],
    )

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
