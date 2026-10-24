"""Output writers for findings and summary JSON artifacts."""

from __future__ import annotations

from pathlib import Path

from razin.constants.reporting import (
    CSV_FINDINGS_FILENAME,
    FINDINGS_FILENAME,
    PURPOSE_ALIGNMENT_FILENAME,
    REPORT_TEMP_PREFIX,
    REPORT_TEMP_SUFFIX,
    SARIF_FINDINGS_FILENAME,
    SCHEMA_VERSION,
    SUMMARY_FILENAME,
)
from razin.io import load_json_file, write_json_atomic
from razin.model import Finding, PurposeAlignmentAssessment, Summary
from razin.scanner.assessment import evidence_verdict_for_package
from razin.scanner.score import (
    aggregate_overall_score,
    aggregate_severity,
    rule_counts,
    severity_counts,
    severity_from_score,
    sorted_top_risks,
)
from razin.types import CoverageStatus, RuleDisableSource, Severity


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
    coverage_status: CoverageStatus = "not-evaluated",
    coverage_reasons: tuple[str, ...] = (),
    purpose_alignment: PurposeAlignmentAssessment | None = None,
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
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
    )
    write_json_atomic(
        path=skill_dir / SUMMARY_FILENAME,
        payload=summary.to_dict(),
        temp_prefix=REPORT_TEMP_PREFIX,
        temp_suffix=REPORT_TEMP_SUFFIX,
    )
    if purpose_alignment is not None:
        write_json_atomic(
            path=skill_dir / PURPOSE_ALIGNMENT_FILENAME,
            payload=purpose_alignment.to_dict(),
            temp_prefix=REPORT_TEMP_PREFIX,
            temp_suffix=REPORT_TEMP_SUFFIX,
        )

    return summary


def remove_stale_reports(out_root: Path, active_names: set[str], output_formats: tuple[str, ...]) -> None:
    """Remove reports absent from this scan, leaving unrelated files alone."""
    for output_format, filename in (("csv", CSV_FINDINGS_FILENAME), ("sarif", SARIF_FINDINGS_FILENAME)):
        path = out_root / filename
        if output_format not in output_formats and not path.is_symlink() and path.is_file():
            path.unlink()

    report_names = (FINDINGS_FILENAME, SUMMARY_FILENAME, PURPOSE_ALIGNMENT_FILENAME)
    for skill_dir in tuple(out_root.iterdir()):
        if skill_dir.name in active_names or skill_dir.is_symlink() or not skill_dir.is_dir():
            continue
        reports = [skill_dir / name for name in report_names]
        summary_path = skill_dir / SUMMARY_FILENAME
        if summary_path.is_symlink() or not summary_path.is_file():
            continue
        try:
            summary = load_json_file(summary_path)
        except (OSError, ValueError):
            continue
        if not (
            isinstance(summary, dict)
            and summary.get("skill") == skill_dir.name
            and isinstance(summary.get("schema_version"), str)
            and isinstance(summary.get("finding_count"), int)
        ):
            continue
        if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in reports):
            continue
        for path in reports:
            if path.is_file():
                path.unlink()
        if not any(skill_dir.iterdir()):
            skill_dir.rmdir()


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
    coverage_status: CoverageStatus = "not-evaluated",
    coverage_reasons: tuple[str, ...] = (),
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
            "signal_kind": finding.signal_kind,
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
        review_priority=overall_score,
        review_priority_level=overall_severity,
        evidence_verdict=evidence_verdict_for_package(source_findings),
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
        shown_finding_count=(len(findings) if all_findings is not None else None),
        output_filter=output_filter,
        rule_overrides=rule_overrides,
        rules_executed=rules_executed,
        rules_disabled=rules_disabled,
        disable_sources=disable_sources,
    )
