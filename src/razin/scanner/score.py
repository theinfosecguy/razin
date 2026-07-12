"""Scoring utilities for findings and summaries."""

from __future__ import annotations

from collections import Counter

from razin.constants.scoring import HIGH_SEVERITY_MIN_SCORE, MEDIUM_SEVERITY_MIN_SCORE, TOP_RISKS_DEFAULT_LIMIT
from razin.model import Finding
from razin.scanner.assessment import review_priority_score, signal_kind_for_rule
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
    min_rule_score: int | None = None,
) -> int:
    """Compatibility alias for the non-probabilistic review-priority score.

    ``min_rule_score`` remains accepted for API compatibility but no longer
    changes the result. Correlated detector values are never combined as if
    they were independent probabilities.
    """
    del min_rule_score
    return review_priority_score(findings)


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings by severity with stable keys."""
    counts = Counter(finding.severity for finding in findings)
    return {
        "high": int(counts.get("high", 0)),
        "medium": int(counts.get("medium", 0)),
        "low": int(counts.get("low", 0)),
    }


def rule_counts(findings: list[Finding]) -> dict[str, int]:
    """Count findings by rule identifier."""
    counts = Counter(finding.rule_id for finding in findings)
    return {rule_id: int(count) for rule_id, count in sorted(counts.items())}


def sorted_top_risks(
    findings: list[Finding],
    limit: int = TOP_RISKS_DEFAULT_LIMIT,
) -> list[Finding]:
    """Return actionable evidence first, then context, sorted deterministically."""

    def sort_key(finding: Finding) -> tuple[int, int, str]:
        is_actionable = finding.classification == "security" and signal_kind_for_rule(finding.rule_id) != "capability"
        return (0 if is_actionable else 1, -finding.score, finding.id)

    return sorted(findings, key=sort_key)[:limit]
