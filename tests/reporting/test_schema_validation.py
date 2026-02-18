"""Tests for JSON Schema validation of findings and summary outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import jsonschema
import pytest

from razin.constants.reporting import SCHEMA_VERSION
from razin.model import Evidence, Finding
from razin.reporting.writer import build_summary, write_skill_reports

SCHEMAS_DIR: Path = Path(__file__).resolve().parents[2] / "schemas"
FINDINGS_SCHEMA_PATH: Path = SCHEMAS_DIR / "findings.schema.json"
SUMMARY_SCHEMA_PATH: Path = SCHEMAS_DIR / "summary.schema.json"


def _load_schema(path: Path) -> dict[str, Any]:
    """Load a JSON Schema file from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def _make_finding(
    *,
    fid: str = "f-001",
    rule_id: str = "NET_RAW_IP",
    score: int = 70,
    severity: Literal["low", "medium", "high"] = "high",
    skill: str = "test-skill",
    path: str = "SKILL.md",
    line: int | None = 1,
) -> Finding:
    """Create a minimal Finding for testing."""
    return Finding(
        id=fid,
        severity=severity,
        score=score,
        confidence="high",
        title=f"{rule_id} finding",
        description=f"Description for {rule_id}",
        evidence=Evidence(path=path, line=line, snippet="snippet"),
        skill=skill,
        rule_id=rule_id,
        recommendation=f"Fix {rule_id}",
    )


@pytest.fixture()
def findings_schema() -> dict[str, Any]:
    """Load the findings JSON Schema."""
    return _load_schema(FINDINGS_SCHEMA_PATH)


@pytest.fixture()
def summary_schema() -> dict[str, Any]:
    """Load the summary JSON Schema."""
    return _load_schema(SUMMARY_SCHEMA_PATH)


@pytest.fixture()
def sample_findings() -> list[Finding]:
    """Create a set of findings spanning all severities."""
    return [
        _make_finding(fid="f-001", rule_id="NET_RAW_IP", score=70, severity="high"),
        _make_finding(fid="f-002", rule_id="SECRET_REF", score=50, severity="medium"),
        _make_finding(fid="f-003", rule_id="EXEC_FIELDS", score=30, severity="low"),
    ]


def test_findings_schema_is_valid_json_schema(findings_schema: dict[str, Any]) -> None:
    """Findings schema itself must be a valid JSON Schema document."""
    jsonschema.Draft202012Validator.check_schema(findings_schema)


def test_summary_schema_is_valid_json_schema(summary_schema: dict[str, Any]) -> None:
    """Summary schema itself must be a valid JSON Schema document."""
    jsonschema.Draft202012Validator.check_schema(summary_schema)


def test_findings_payload_validates(
    sample_findings: list[Finding],
    findings_schema: dict[str, Any],
) -> None:
    """Serialized findings array must conform to the findings schema."""
    payload = [f.to_dict() for f in sample_findings]
    jsonschema.validate(instance=payload, schema=findings_schema)


def test_summary_payload_validates(
    sample_findings: list[Finding],
    summary_schema: dict[str, Any],
) -> None:
    """Built summary must conform to the summary schema."""
    summary = build_summary("test-skill", sample_findings)
    jsonschema.validate(instance=summary.to_dict(), schema=summary_schema)


def test_summary_contains_schema_version(sample_findings: list[Finding]) -> None:
    """Summary output must include schema_version matching the constant."""
    summary = build_summary("test-skill", sample_findings)
    payload = summary.to_dict()
    assert payload["schema_version"] == SCHEMA_VERSION


def test_summary_includes_rule_selection_metadata(sample_findings: list[Finding]) -> None:
    """Summary exposes rule execution/disable metadata when provided."""
    summary = build_summary(
        "test-skill",
        sample_findings,
        rules_executed=("SECRET_REF",),
        rules_disabled=("MCP_REQUIRED",),
        disable_sources={"MCP_REQUIRED": "config"},
    )
    payload = summary.to_dict()
    assert payload["rules_executed"] == ["SECRET_REF"]
    assert payload["rules_disabled"] == ["MCP_REQUIRED"]
    assert payload["disable_sources"] == {"MCP_REQUIRED": "config"}


def test_empty_findings_validates(findings_schema: dict[str, Any]) -> None:
    """An empty findings array must be valid."""
    jsonschema.validate(instance=[], schema=findings_schema)


def test_empty_findings_summary_validates(summary_schema: dict[str, Any]) -> None:
    """Summary built from zero findings must be valid."""
    summary = build_summary("empty-skill", [])
    jsonschema.validate(instance=summary.to_dict(), schema=summary_schema)


def test_finding_with_null_line_validates(findings_schema: dict[str, Any]) -> None:
    """A finding with null evidence line must be valid."""
    finding = _make_finding(line=None)
    payload = [finding.to_dict()]
    jsonschema.validate(instance=payload, schema=findings_schema)


def test_findings_missing_required_field_rejected(findings_schema: dict[str, Any]) -> None:
    """A finding missing a required field must fail validation."""
    payload = [{"id": "f-001", "severity": "high"}]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=payload, schema=findings_schema)


def test_summary_missing_schema_version_rejected(summary_schema: dict[str, Any]) -> None:
    """A summary without schema_version must fail validation."""
    payload = {
        "skill": "test",
        "overall_score": 50,
        "overall_severity": "medium",
        "finding_count": 0,
        "counts_by_severity": {"low": 0, "medium": 0, "high": 0},
        "top_risks": [],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=payload, schema=summary_schema)


def test_summary_invalid_severity_rejected(summary_schema: dict[str, Any]) -> None:
    """A summary with an invalid severity value must fail validation."""
    payload = {
        "schema_version": SCHEMA_VERSION,
        "skill": "test",
        "overall_score": 50,
        "overall_severity": "critical",
        "finding_count": 0,
        "counts_by_severity": {"low": 0, "medium": 0, "high": 0},
        "top_risks": [],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=payload, schema=summary_schema)


def test_write_skill_reports_outputs_valid_schema(
    tmp_path: Path,
    sample_findings: list[Finding],
    findings_schema: dict[str, Any],
    summary_schema: dict[str, Any],
) -> None:
    """Written findings.json and summary.json must conform to schemas."""
    write_skill_reports(tmp_path, "test-skill", sample_findings)

    findings_path = tmp_path / "test-skill" / "findings.json"
    summary_path = tmp_path / "test-skill" / "summary.json"

    findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))

    jsonschema.validate(instance=findings_data, schema=findings_schema)
    jsonschema.validate(instance=summary_data, schema=summary_schema)

    assert summary_data["schema_version"] == SCHEMA_VERSION
