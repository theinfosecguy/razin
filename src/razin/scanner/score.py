"""Scoring utilities for findings and summaries."""

from __future__ import annotations

from collections import Counter

from razin.constants.scoring import (
    AGGREGATE_MIN_RULE_SCORE,
    HIGH_SEVERITY_MIN_SCORE,
    MEDIUM_SEVERITY_MIN_SCORE,
    TOP_RISKS_DEFAULT_LIMIT,
)
from razin.model import Finding
from razin.types import Severity


def severity_from_score(score: int) -> Severity:
    """Map 0-100 score to severity label using fixed thresholds.

    Used for individual finding severity.  For aggregate severity
    that respects profile thresholds, use ``aggregate_severity``.
    """
    if score >= HIGH_SEVERITY_MIN_SCORE:
        return "high"
    if score >= MEDIUM_SEVERITY_MIN_SCORE:
        return "medium"
    return "low"


def aggregate_severity(
    score: int,
    *,
    high_min: int = HIGH_SEVERITY_MIN_SCORE,
    medium_min: int = MEDIUM_SEVERITY_MIN_SCORE,
) -> Severity:
    """Map aggregate score to severity using profile-aware thresholds."""
    if score >= high_min:
        return "high"
    if score >= medium_min:
        return "medium"
    return "low"


def aggregate_overall_score(
    findings: list[Finding],
    *,
    min_rule_score: int = AGGREGATE_MIN_RULE_SCORE,
) -> int:
    """Aggregate finding scores into a single 0-100 overall score.

    Uses two-level dampening to prevent score saturation:

    1. Per-rule dampening: for each rule_id, only the highest score is kept.
       This prevents N findings from the same detector from saturating the
       aggregate.
    2. Significance threshold: only rules whose max score reaches
       *min_rule_score* contribute to the probabilistic-OR aggregate.

    The probabilistic-OR combination is then applied across the deduplicated
    representative scores.

    Parameters

    findings:
        List of findings to aggregate.
    min_rule_score:
        Per-rule max must reach this threshold to contribute.  Defaults to
        ``AGGREGATE_MIN_RULE_SCORE`` but can be overridden per policy profile.
    """
    if not findings:
        return 0

    # Level 1: Per-rule dampening — take max score per rule_id.
    rule_max: dict[str, int] = {}
    for finding in findings:
        current = rule_max.get(finding.rule_id, 0)
        if finding.score > current:
            rule_max[finding.rule_id] = finding.score

    # Level 2: Significance threshold — only rules whose max score reaches
    # min_rule_score contribute to the probabilistic-OR aggregate.
    # Lower-scoring rules are informational context signals that are still
    # reported as findings but don't inflate the aggregate.
    significant_scores = [score for score in rule_max.values() if score >= min_rule_score]

    if not significant_scores:
        # Fall back to the single highest per-rule score if nothing
        # crosses the significance threshold.
        return max(rule_max.values())

    representative_scores: set[int] = set(significant_scores)

    probabilities = [max(0.0, min(1.0, score / 100.0)) for score in representative_scores]
    # Probabilistic OR across independent risk signals: 1 - Π(1 - p_i).
    residual = 1.0
    for probability in probabilities:
        residual *= 1.0 - probability
    combined = 1.0 - residual
    return int(round(combined * 100))


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings by severity with stable keys."""
    counts = Counter(finding.severity for finding in findings)
    return {
        "high": int(counts.get("high", 0)),
        "medium": int(counts.get("medium", 0)),
        "low": int(counts.get("low", 0)),
    }


def sorted_top_risks(
    findings: list[Finding],
    limit: int = TOP_RISKS_DEFAULT_LIMIT,
) -> list[Finding]:
    """Return highest-risk findings sorted deterministically."""
    return sorted(findings, key=lambda finding: (-finding.score, finding.id))[:limit]
