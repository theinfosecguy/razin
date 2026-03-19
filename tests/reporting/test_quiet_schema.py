"""Tests for quiet stream JSONL schema validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from razin.model import Evidence, Finding, ScanResult
from razin.reporting.quiet_writer import write_quiet_output

SCHEMAS_DIR: Path = Path(__file__).resolve().parents[2] / "schemas"
QUIET_SCHEMA_PATH: Path = SCHEMAS_DIR / "quiet_stream.schema.json"


def _load_schema() -> dict[str, Any]:
    """Load the quiet stream JSON schema."""
    return json.loads(QUIET_SCHEMA_PATH.read_text(encoding="utf-8"))


def _dummy_finding() -> Finding:
    """Build a minimal Finding for schema tests."""
    return Finding(
        id="f-001",
        severity="medium",
        score=55,
        confidence="high",
        title="Test finding",
        description="A test finding.",
        evidence=Evidence(path="skills/test/SKILL.md", line=5, snippet="test"),
        skill="test-skill",
        rule_id="TEST_RULE",
        recommendation="Fix it.",
        classification="security",
    )


def _dummy_result(
    findings: tuple[Finding, ...] = (),
    warnings: tuple[str, ...] = (),
) -> ScanResult:
    """Build a minimal ScanResult for schema tests."""
    return ScanResult(
        scanned_files=1,
        total_findings=len(findings),
        aggregate_score=max((f.score for f in findings), default=0),
        aggregate_severity="low",
        counts_by_severity={"low": 0, "medium": 0, "high": 0},
        findings=findings,
        duration_seconds=0.5,
        warnings=warnings,
        cache_hits=0,
        cache_misses=1,
    )


def test_finding_record_validates(tmp_path: Path) -> None:
    """Finding records validate against the quiet stream schema."""
    schema = _load_schema()
    out = tmp_path / "out.jsonl"
    result = _dummy_result(findings=(_dummy_finding(),))
    write_quiet_output(out_path=out, result=result, include_summary=False, include_warnings=False)

    for line in out.read_text(encoding="utf-8").strip().splitlines():
        record = json.loads(line)
        jsonschema.validate(record, schema)


def test_warning_record_validates(tmp_path: Path) -> None:
    """Warning records validate against the quiet stream schema."""
    schema = _load_schema()
    out = tmp_path / "out.jsonl"
    result = _dummy_result(warnings=("test warning",))
    write_quiet_output(out_path=out, result=result, include_summary=False)

    for line in out.read_text(encoding="utf-8").strip().splitlines():
        record = json.loads(line)
        jsonschema.validate(record, schema)


def test_summary_record_validates(tmp_path: Path) -> None:
    """Summary records validate against the quiet stream schema."""
    schema = _load_schema()
    out = tmp_path / "out.jsonl"
    result = _dummy_result(findings=(_dummy_finding(),))
    write_quiet_output(out_path=out, result=result, include_warnings=False)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    summary_lines = [line for line in lines if '"type": "summary"' in line]
    assert len(summary_lines) == 1
    record = json.loads(summary_lines[0])
    jsonschema.validate(record, schema)


def test_all_record_types_validate_together(tmp_path: Path) -> None:
    """Full output with finding, warning, and summary all validates."""
    schema = _load_schema()
    out = tmp_path / "out.jsonl"
    result = _dummy_result(findings=(_dummy_finding(),), warnings=("test warn",))
    write_quiet_output(out_path=out, result=result, gate_failed=True)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    types_seen: set[str] = set()
    for line in lines:
        record = json.loads(line)
        jsonschema.validate(record, schema)
        types_seen.add(record["type"])
    assert types_seen == {"finding", "warning", "summary"}


def test_filtered_output_validates(tmp_path: Path) -> None:
    """Filtered output (min_severity) validates against schema."""
    schema = _load_schema()
    out = tmp_path / "out.jsonl"
    low = Finding(
        id="f-low",
        severity="low",
        score=20,
        confidence="low",
        title="Low",
        description="Low severity.",
        evidence=Evidence(path="SKILL.md", line=1, snippet="x"),
        skill="s",
        rule_id="R",
        recommendation="r",
        classification="informational",
    )
    high = _dummy_finding()
    result = _dummy_result(findings=(low, high))
    write_quiet_output(out_path=out, result=result, min_severity="medium")

    for line in out.read_text(encoding="utf-8").strip().splitlines():
        record = json.loads(line)
        jsonschema.validate(record, schema)


@pytest.mark.parametrize(
    "record_type,bad_data",
    [
        pytest.param("finding", {"message": "oops"}, id="finding-with-warning-data"),
        pytest.param(
            "warning",
            {
                "id": "f-1",
                "severity": "low",
                "score": 10,
                "confidence": "low",
                "title": "t",
                "description": "d",
                "evidence": {"path": "p", "line": 1, "snippet": "s"},
                "skill": "s",
                "rule_id": "R",
                "recommendation": "r",
                "classification": "security",
            },
            id="warning-with-finding-data",
        ),
        pytest.param("summary", {"message": "oops"}, id="summary-with-warning-data"),
    ],
)
def test_schema_rejects_mismatched_type_and_data(record_type: str, bad_data: dict[str, Any]) -> None:
    """Schema rejects records where type and data shape do not match."""
    schema = _load_schema()
    record = {
        "type": record_type,
        "version": "1.0.0",
        "timestamp": "2026-03-16T00:00:00+00:00",
        "data": bad_data,
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, schema)
