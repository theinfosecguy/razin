"""Finding conversion and deduplication helpers for the scanner pipeline."""

from __future__ import annotations

import hashlib
import logging
from typing import cast

from razin.constants.ids import FINDING_ID_HEX_LENGTH
from razin.model import Evidence, Finding, FindingCandidate
from razin.scanner.score import aggregate_severity
from razin.types import Confidence, Severity

logger = logging.getLogger(__name__)


def candidate_to_finding(
    skill_name: str,
    candidate: FindingCandidate,
    *,
    high_severity_min: int = 70,
    medium_severity_min: int = 40,
) -> Finding:
    """Convert a finding candidate into a stable, serialized finding."""
    score = max(0, min(100, int(candidate.score)))
    severity = aggregate_severity(score, high_min=high_severity_min, medium_min=medium_severity_min)

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
    )


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
