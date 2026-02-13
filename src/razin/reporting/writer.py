"""Output writers for findings and summary JSON artifacts."""

from __future__ import annotations

from pathlib import Path

from razin.constants.reporting import (
    FINDINGS_FILENAME,
    REPORT_TEMP_PREFIX,
    REPORT_TEMP_SUFFIX,
    SUMMARY_FILENAME,
)
from razin.io import write_json_atomic
from razin.model import Finding, Summary
from razin.scanner.score import (
    aggregate_overall_score,
    aggregate_severity,
    severity_counts,
    severity_from_score,
    sorted_top_risks,
)


def write_skill_reports(
    out_root: Path,
    skill_name: str,
    findings: list[Finding],
    *,
    min_rule_score: int | None = None,
    high_severity_min: int | None = None,
    medium_severity_min: int | None = None,
) -> Summary:
    """Write findings and summary JSON for a skill and return the summary."""
    skill_dir = out_root / skill_name
    skill_dir.mkdir(parents=True, exist_ok=True)

    sorted_findings = sorted(findings, key=lambda finding: finding.id)
    findings_payload = [finding.to_dict() for finding in sorted_findings]
    write_json_atomic(
        path=skill_dir / FINDINGS_FILENAME,
        payload=findings_payload,
        temp_prefix=REPORT_TEMP_PREFIX,
        temp_suffix=REPORT_TEMP_SUFFIX,
    )

    summary = build_summary(
        skill_name,
        sorted_findings,
        min_rule_score=min_rule_score,
        high_severity_min=high_severity_min,
        medium_severity_min=medium_severity_min,
    )
    write_json_atomic(
        path=skill_dir / SUMMARY_FILENAME,
        payload=summary.to_dict(),
        temp_prefix=REPORT_TEMP_PREFIX,
        temp_suffix=REPORT_TEMP_SUFFIX,
    )

    return summary


def build_summary(
    skill_name: str,
    findings: list[Finding],
    *,
    min_rule_score: int | None = None,
    high_severity_min: int | None = None,
    medium_severity_min: int | None = None,
) -> Summary:
    """Build a deterministic per-skill summary from findings."""
    score_kwargs = {}
    if min_rule_score is not None:
        score_kwargs["min_rule_score"] = min_rule_score
    overall_score = aggregate_overall_score(findings, **score_kwargs)

    sev_kwargs: dict[str, int] = {}
    if high_severity_min is not None:
        sev_kwargs["high_min"] = high_severity_min
    if medium_severity_min is not None:
        sev_kwargs["medium_min"] = medium_severity_min
    overall_severity = (
        aggregate_severity(overall_score, **sev_kwargs) if sev_kwargs else severity_from_score(overall_score)
    )
    counts = severity_counts(findings)

    top_risks = [
        {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "score": finding.score,
            "evidence": {
                "path": finding.evidence.path,
                "line": finding.evidence.line,
                "snippet": finding.evidence.snippet,
            },
        }
        for finding in sorted_top_risks(findings)
    ]

    return Summary(
        skill=skill_name,
        overall_score=overall_score,
        overall_severity=overall_severity,
        finding_count=len(findings),
        counts_by_severity=counts,
        top_risks=tuple(top_risks),
    )
