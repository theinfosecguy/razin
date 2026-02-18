"""Output writers for findings and summary JSON artifacts."""

from __future__ import annotations

from pathlib import Path

from razin.constants.reporting import (
    FINDINGS_FILENAME,
    REPORT_TEMP_PREFIX,
    REPORT_TEMP_SUFFIX,
    SCHEMA_VERSION,
    SUMMARY_FILENAME,
)
from razin.io import write_json_atomic
from razin.model import Finding, Summary
from razin.scanner.score import (
    aggregate_overall_score,
    aggregate_severity,
    rule_counts,
    severity_counts,
    severity_from_score,
    sorted_top_risks,
)
from razin.types import RuleDisableSource, Severity


def write_skill_reports(
    out_root: Path,
    skill_name: str,
    findings: list[Finding],
    *,
    all_findings: list[Finding] | None = None,
    min_rule_score: int | None = None,
    high_severity_min: int | None = None,
    medium_severity_min: int | None = None,
    output_filter: dict[str, object] | None = None,
    rule_overrides: dict[str, dict[str, Severity]] | None = None,
    rules_executed: tuple[str, ...] | None = None,
    rules_disabled: tuple[str, ...] | None = None,
    disable_sources: dict[str, RuleDisableSource] | None = None,
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
        all_findings=all_findings,
        min_rule_score=min_rule_score,
        high_severity_min=high_severity_min,
        medium_severity_min=medium_severity_min,
        output_filter=output_filter,
        rule_overrides=rule_overrides,
        rules_executed=rules_executed,
        rules_disabled=rules_disabled,
        disable_sources=disable_sources,
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
    all_findings: list[Finding] | None = None,
    min_rule_score: int | None = None,
    high_severity_min: int | None = None,
    medium_severity_min: int | None = None,
    output_filter: dict[str, object] | None = None,
    rule_overrides: dict[str, dict[str, Severity]] | None = None,
    rules_executed: tuple[str, ...] | None = None,
    rules_disabled: tuple[str, ...] | None = None,
    disable_sources: dict[str, RuleDisableSource] | None = None,
) -> Summary:
    """Build a deterministic per-skill summary from findings."""
    source_findings = all_findings if all_findings is not None else findings

    score_kwargs = {}
    if min_rule_score is not None:
        score_kwargs["min_rule_score"] = min_rule_score
    overall_score = aggregate_overall_score(source_findings, **score_kwargs)

    sev_kwargs: dict[str, int] = {}
    if high_severity_min is not None:
        sev_kwargs["high_min"] = high_severity_min
    if medium_severity_min is not None:
        sev_kwargs["medium_min"] = medium_severity_min
    overall_severity = (
        aggregate_severity(overall_score, **sev_kwargs) if sev_kwargs else severity_from_score(overall_score)
    )
    counts = severity_counts(source_findings)
    by_rule = rule_counts(source_findings)

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
        for finding in sorted_top_risks(source_findings)
    ]

    return Summary(
        schema_version=SCHEMA_VERSION,
        skill=skill_name,
        overall_score=overall_score,
        overall_severity=overall_severity,
        finding_count=len(source_findings),
        counts_by_severity=counts,
        counts_by_rule=by_rule,
        top_risks=tuple(top_risks),
        shown_finding_count=(len(findings) if all_findings is not None else None),
        output_filter=output_filter,
        rule_overrides=rule_overrides,
        rules_executed=rules_executed,
        rules_disabled=rules_disabled,
        disable_sources=disable_sources,
    )
