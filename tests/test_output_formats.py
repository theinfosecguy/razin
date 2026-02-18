"""Tests for CSV and SARIF output format writers and CLI format parsing."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Literal

import pytest

from razin.cli.main import build_parser, main
from razin.model import Evidence, Finding
from razin.reporting.csv_writer import render_csv_string, write_csv_findings
from razin.reporting.sarif_writer import build_sarif_envelope, write_sarif_findings


def _make_finding(
    *,
    rule_id: str = "NET_RAW_IP",
    score: int = 70,
    severity: Literal["low", "medium", "high"] = "high",
    skill: str = "test-skill",
    fid: str = "f-001",
    path: str = "SKILL.md",
    line: int | None = 1,
) -> Finding:
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
def sample_findings() -> list[Finding]:
    return [
        _make_finding(fid="f-001", rule_id="NET_RAW_IP", score=70, severity="high"),
        _make_finding(fid="f-002", rule_id="SECRET_REF", score=50, severity="medium"),
        _make_finding(fid="f-003", rule_id="EXEC_FIELDS", score=30, severity="low"),
    ]


class TestOutputFormatParsing:
    """CLI --output-format parsing and validation."""

    def test_default_format_is_json(self, tmp_path: Path) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "-r", str(tmp_path)])
        assert args.output_format == "json"

    def test_single_csv_format(self, tmp_path: Path) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "-r", str(tmp_path), "--output-format", "csv"])
        assert args.output_format == "csv"

    def test_multi_format_accepted(self, tmp_path: Path) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "-r", str(tmp_path), "--output-format", "json,csv,sarif"])
        assert args.output_format == "json,csv,sarif"

    def test_invalid_format_rejected(self, capsys) -> None:  # type: ignore[no-untyped-def]
        code = main(["scan", "-r", ".", "--output-format", "xml", "--no-stdout"])
        captured = capsys.readouterr()
        assert code == 2
        assert "unknown output format" in captured.err

    def test_mixed_valid_invalid_rejected(self, capsys) -> None:  # type: ignore[no-untyped-def]
        code = main(["scan", "-r", ".", "--output-format", "json,xml", "--no-stdout"])
        captured = capsys.readouterr()
        assert code == 2
        assert "xml" in captured.err


class TestCsvWriter:
    """CSV findings writer."""

    def test_csv_header_columns(self, sample_findings: list[Finding]) -> None:
        output = render_csv_string(sample_findings)
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        assert header == [
            "id",
            "skill",
            "rule_id",
            "severity",
            "classification",
            "score",
            "confidence",
            "path",
            "line",
            "title",
            "description",
            "recommendation",
        ]

    def test_csv_row_count(self, sample_findings: list[Finding]) -> None:
        output = render_csv_string(sample_findings)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 4  # header + 3 findings

    def test_csv_includes_classification_column(self, sample_findings: list[Finding]) -> None:
        output = render_csv_string(sample_findings)
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[4] == "security"

    def test_csv_deterministic_order(self, sample_findings: list[Finding]) -> None:
        output = render_csv_string(sample_findings)
        reader = csv.reader(io.StringIO(output))
        next(reader)  # skip header
        scores = [int(row[5]) for row in reader]
        assert scores == sorted(scores, reverse=True)

    def test_csv_write_file(self, tmp_path: Path, sample_findings: list[Finding]) -> None:
        path = write_csv_findings(tmp_path, sample_findings)
        assert path.exists()
        assert path.name == "findings.csv"
        content = path.read_text(encoding="utf-8")
        assert "NET_RAW_IP" in content

    def test_csv_null_line_renders_empty(self) -> None:
        f = _make_finding(line=None)
        output = render_csv_string([f])
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[8] == ""  # line column

    def test_csv_escapes_commas_in_description(self) -> None:
        f = Finding(
            id="f-esc",
            severity="low",
            score=10,
            confidence="low",
            title="Test, with comma",
            description='Value contains, commas and "quotes"',
            evidence=Evidence(path="SKILL.md", line=1, snippet="s"),
            skill="test",
            rule_id="TEST",
            recommendation="Fix it",
        )
        output = render_csv_string([f])
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[10] == 'Value contains, commas and "quotes"'


class TestSarifWriter:
    """SARIF 2.1.0 findings writer."""

    def test_sarif_envelope_version(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        assert envelope["version"] == "2.1.0"
        assert "$schema" in envelope

    def test_sarif_tool_name(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        driver = envelope["runs"][0]["tool"]["driver"]
        assert driver["name"] == "RAZIN"
        assert "version" in driver

    def test_sarif_result_count(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        results = envelope["runs"][0]["results"]
        assert len(results) == 3

    def test_sarif_severity_mapping(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        results = envelope["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["NET_RAW_IP"] == "error"
        assert levels["SECRET_REF"] == "warning"
        assert levels["EXEC_FIELDS"] == "note"

    def test_sarif_result_has_location(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        result = envelope["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc
        assert loc["region"]["startLine"] == 1

    def test_sarif_partial_fingerprints(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        result = envelope["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "findingId" in result["partialFingerprints"]

    def test_sarif_result_includes_classification(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        result = envelope["runs"][0]["results"][0]
        assert result["properties"]["classification"] == "security"

    def test_sarif_rules_derived_from_findings(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        rules = envelope["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert sorted(rule_ids) == ["EXEC_FIELDS", "NET_RAW_IP", "SECRET_REF"]

    def test_sarif_deterministic_order(self, sample_findings: list[Finding]) -> None:
        envelope = build_sarif_envelope(sample_findings)
        results = envelope["runs"][0]["results"]
        scores = [r["properties"]["score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_sarif_write_file(self, tmp_path: Path, sample_findings: list[Finding]) -> None:
        path = write_sarif_findings(tmp_path, sample_findings)
        assert path.exists()
        assert path.name == "findings.sarif"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"

    def test_sarif_null_line_omits_region(self) -> None:
        f = _make_finding(line=None)
        envelope = build_sarif_envelope([f])
        loc = envelope["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "region" not in loc

    def test_sarif_empty_findings(self) -> None:
        envelope = build_sarif_envelope([])
        assert envelope["runs"][0]["results"] == []
        assert envelope["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_run_properties_include_distribution_and_filter_metadata(self) -> None:
        envelope = build_sarif_envelope(
            [_make_finding(rule_id="SECRET_REF", score=80, severity="high")],
            rule_distribution={"SECRET_REF": 4, "MCP_REQUIRED": 10},
            filter_metadata={"shown": 1, "total": 14, "filtered": 13, "min_severity": "high", "security_only": True},
            rule_overrides={"MCP_REQUIRED": {"max_severity": "low"}},
            rules_executed=("SECRET_REF",),
            rules_disabled=("MCP_REQUIRED",),
            disable_sources={"MCP_REQUIRED": "config"},
        )
        props = envelope["runs"][0]["properties"]
        assert props["ruleDistribution"]["SECRET_REF"] == 4
        assert props["filter"]["shown"] == 1
        assert props["ruleOverrides"]["MCP_REQUIRED"]["max_severity"] == "low"
        assert props["rules_executed"] == ["SECRET_REF"]
        assert props["rules_disabled"] == ["MCP_REQUIRED"]
        assert props["disable_sources"]["MCP_REQUIRED"] == "config"
