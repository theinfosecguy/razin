"""Finding conversion and deduplication helpers for the scanner pipeline."""

from __future__ import annotations

import hashlib
import logging
from typing import cast

from razin.constants.ids import FINDING_ID_HEX_LENGTH
from razin.constants.scoring import SEVERITY_RANK
from razin.model import Evidence, Finding, FindingCandidate, SeverityOverride
from razin.scanner.score import aggregate_severity
from razin.types import Classification, Confidence, RuleOverrideConfig, Severity

logger = logging.getLogger(__name__)


def candidate_to_finding(
    skill_name: str,
    candidate: FindingCandidate,
    *,
    rule_override: RuleOverrideConfig | None = None,
    high_severity_min: int = 70,
    medium_severity_min: int = 40,
) -> Finding:
    """Convert a finding candidate into a stable, serialized finding."""
    score = max(0, min(100, int(candidate.score)))
    severity = aggregate_severity(score, high_min=high_severity_min, medium_min=medium_severity_min)
    severity_override: SeverityOverride | None = None

    if rule_override is not None and (rule_override.max_severity is not None or rule_override.min_severity is not None):
        score, severity, severity_override = _apply_rule_override(
            score=score,
            severity=severity,
            rule_override=rule_override,
            high_severity_min=high_severity_min,
            medium_severity_min=medium_severity_min,
        )

    identity = "|".join(
        [
            skill_name,
            candidate.rule_id,
            candidate.title,
            candidate.description,
            candidate.evidence.path,
            str(candidate.evidence.line),
            candidate.evidence.snippet,
        ]
    )
    finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:FINDING_ID_HEX_LENGTH]

    return Finding(
        id=finding_id,
        severity=severity,
        score=score,
        confidence=candidate.confidence,
        title=candidate.title,
        description=candidate.description,
        evidence=candidate.evidence,
        skill=skill_name,
        rule_id=candidate.rule_id,
        recommendation=candidate.recommendation,
        classification=candidate.classification,
        severity_override=severity_override,
    )


def _apply_rule_override(
    *,
    score: int,
    severity: Severity,
    rule_override: RuleOverrideConfig,
    high_severity_min: int,
    medium_severity_min: int,
) -> tuple[int, Severity, SeverityOverride | None]:
    """Apply per-rule min/max severity policy and emit audit metadata when changed."""
    adjusted_score = score
    adjusted_severity = severity
    min_severity = rule_override.min_severity
    max_severity = rule_override.max_severity

    if min_severity is not None and SEVERITY_RANK[adjusted_severity] < SEVERITY_RANK[min_severity]:
        adjusted_score = _raise_score_to_min_severity(
            score=adjusted_score,
            min_severity=min_severity,
            high_severity_min=high_severity_min,
            medium_severity_min=medium_severity_min,
        )
        adjusted_severity = aggregate_severity(
            adjusted_score,
            high_min=high_severity_min,
            medium_min=medium_severity_min,
        )
        if SEVERITY_RANK[adjusted_severity] < SEVERITY_RANK[min_severity]:
            adjusted_severity = min_severity

    if max_severity is not None and SEVERITY_RANK[adjusted_severity] > SEVERITY_RANK[max_severity]:
        adjusted_score = _cap_score_to_max_severity(
            score=adjusted_score,
            max_severity=max_severity,
            high_severity_min=high_severity_min,
            medium_severity_min=medium_severity_min,
        )
        adjusted_severity = aggregate_severity(
            adjusted_score,
            high_min=high_severity_min,
            medium_min=medium_severity_min,
        )
        if SEVERITY_RANK[adjusted_severity] > SEVERITY_RANK[max_severity]:
            adjusted_severity = max_severity

    if adjusted_score == score and adjusted_severity == severity:
        return score, severity, None

    return (
        adjusted_score,
        adjusted_severity,
        SeverityOverride(
            original=severity,
            applied=adjusted_severity,
            reason="rule_override",
        ),
    )


def _cap_score_to_max_severity(
    *,
    score: int,
    max_severity: Severity,
    high_severity_min: int,
    medium_severity_min: int,
) -> int:
    """Cap a score so profile thresholds cannot exceed the requested severity."""
    if max_severity == "high":
        return score
    if max_severity == "medium":
        return min(score, max(0, high_severity_min - 1))
    return min(score, max(0, medium_severity_min - 1))


def _raise_score_to_min_severity(
    *,
    score: int,
    min_severity: Severity,
    high_severity_min: int,
    medium_severity_min: int,
) -> int:
    """Raise a score so profile thresholds cannot fall below requested severity."""
    if min_severity == "low":
        return score
    if min_severity == "medium":
        return max(score, medium_severity_min)
    return max(score, high_severity_min)


def suppress_redundant_candidates(candidates: list[FindingCandidate]) -> list[FindingCandidate]:
    """Suppress lower-value findings already covered by stronger MCP evidence.

    Domain findings (``NET_UNKNOWN_DOMAIN``, ``NET_DOC_DOMAIN``) are only
    suppressed when their score does not exceed the MCP_ENDPOINT score on the
    same evidence line.
    """
    mcp_scores: dict[tuple[str, int | None], int] = {}
    for candidate in candidates:
        if candidate.rule_id == "MCP_ENDPOINT":
            key = (candidate.evidence.path, candidate.evidence.line)
            existing = mcp_scores.get(key, 0)
            if candidate.score > existing:
                mcp_scores[key] = candidate.score
    if not mcp_scores:
        return candidates

    kept: list[FindingCandidate] = []
    for candidate in candidates:
        evidence_key = (candidate.evidence.path, candidate.evidence.line)
        if (
            candidate.rule_id in {"NET_UNKNOWN_DOMAIN", "NET_DOC_DOMAIN"}
            and evidence_key in mcp_scores
            and candidate.score <= mcp_scores[evidence_key]
        ):
            continue
        kept.append(candidate)

    return kept


def deserialize_findings(payload: object) -> list[Finding]:
    """Deserialize cached finding payload dictionaries into Finding models."""
    if not isinstance(payload, list):
        logger.debug("Cache entry findings is not a list, skipping")
        return []

    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            logger.debug("Skipping malformed cache finding entry: %s", type(item).__name__)
            continue

        evidence_payload = item.get("evidence", {})
        if not isinstance(evidence_payload, dict):
            evidence_payload = {}

        findings.append(
            Finding(
                id=str(item.get("id", "")),
                severity=as_severity(item.get("severity")),
                score=int(item.get("score", 0)),
                confidence=as_confidence(item.get("confidence")),
                title=str(item.get("title", "")),
                description=str(item.get("description", "")),
                evidence=Evidence(
                    path=str(evidence_payload.get("path", "")),
                    line=(int(evidence_payload["line"]) if evidence_payload.get("line") is not None else None),
                    snippet=str(evidence_payload.get("snippet", "")),
                ),
                skill=str(item.get("skill", "")),
                rule_id=str(item.get("rule_id", "")),
                recommendation=str(item.get("recommendation", "")),
                classification=as_classification(item.get("classification")),
                severity_override=_deserialize_severity_override(item.get("severity_override")),
            )
        )

    return findings


def as_severity(value: object) -> Severity:
    """Coerce an arbitrary value into a valid severity enum."""
    if isinstance(value, str) and value in {"low", "medium", "high"}:
        return cast(Severity, value)
    return "low"


def as_confidence(value: object) -> Confidence:
    """Coerce an arbitrary value into a valid confidence enum."""
    if isinstance(value, str) and value in {"low", "medium", "high"}:
        return cast(Confidence, value)
    return "low"


def as_classification(value: object) -> Classification:
    """Coerce an arbitrary value into a valid classification enum."""
    if isinstance(value, str) and value in {"security", "informational"}:
        return cast(Classification, value)
    return "security"


def _deserialize_severity_override(value: object) -> SeverityOverride | None:
    """Deserialize persisted severity override metadata, if present."""
    if not isinstance(value, dict):
        return None
    return SeverityOverride(
        original=as_severity(value.get("original")),
        applied=as_severity(value.get("applied")),
        reason=str(value.get("reason", "")),
    )
