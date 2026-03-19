"""Tests for quiet mode: CLI flags, config, writer, schema validation, and zero-stdout."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from razin.cli.main import build_parser, main
from razin.config import load_config
from razin.config.validator import validate_config_file
from razin.constants.validation import CFG004, CFG005, CFG006, CFG009, CFG011
from razin.exceptions import ConfigError
from razin.model import Evidence, Finding, ScanResult
from razin.reporting.quiet_writer import write_quiet_output


def _write_config(tmp_path: Path, content: str) -> Path:
    """Write a razin.yaml config file and return its path."""
    path = tmp_path / "razin.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def _dummy_result(findings: tuple[Finding, ...] = (), warnings: tuple[str, ...] = ()) -> ScanResult:
    """Build a minimal ScanResult for writer tests."""
    return ScanResult(
        scanned_files=1,
        total_findings=len(findings),
        aggregate_score=max((f.score for f in findings), default=0),
        aggregate_severity="low",
        counts_by_severity={"low": 0, "medium": 0, "high": 0},
        findings=findings,
        duration_seconds=0.123,
        warnings=warnings,
        cache_hits=0,
        cache_misses=1,
    )


def _dummy_finding(
    *,
    rule_id: str = "TEST_RULE",
    severity: str = "medium",
    score: int = 55,
    classification: str = "security",
) -> Finding:
    """Build a minimal Finding for writer tests."""
    return Finding(
        id="finding-001",
        severity=severity,  # type: ignore[arg-type]
        score=score,
        confidence="high",
        title="Test finding",
        description="A test finding.",
        evidence=Evidence(path="skills/test/SKILL.md", line=5, snippet="test snippet"),
        skill="test-skill",
        rule_id=rule_id,
        recommendation="Fix it.",
        classification=classification,  # type: ignore[arg-type]
    )


def test_parser_accepts_quiet_flags(tmp_path: Path) -> None:
    """Parser recognizes --quiet-mode and --quiet-output flags."""
    parser = build_parser()
    args = parser.parse_args(
        ["scan", "--root", str(tmp_path), "--quiet-mode", "--quiet-output", str(tmp_path / "out.jsonl")]
    )
    assert args.quiet_mode is True
    assert args.quiet_output == tmp_path / "out.jsonl"


def test_parser_defaults_quiet_off(tmp_path: Path) -> None:
    """Quiet mode is off by default."""
    parser = build_parser()
    args = parser.parse_args(["scan", "--root", str(tmp_path)])
    assert args.quiet_mode is False
    assert args.quiet_output is None


def test_quiet_mode_requires_quiet_output(tmp_path: Path) -> None:
    """Quiet mode without --quiet-output exits with code 2."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# S\n", encoding="utf-8")
    exit_code = main(["scan", "--root", str(tmp_path), "--quiet-mode"])
    assert exit_code == 2


def test_quiet_mode_conflicts_with_output_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Quiet mode rejects -o flag."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# S\n", encoding="utf-8")
    exit_code = main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--quiet-mode",
            "--quiet-output",
            str(tmp_path / "out.jsonl"),
            "-o",
            str(tmp_path / "out"),
        ]
    )
    assert exit_code == 2
    assert "conflicts with" in capsys.readouterr().err


def test_quiet_mode_conflicts_with_group_by(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Quiet mode rejects --group-by flag."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# S\n", encoding="utf-8")
    exit_code = main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--quiet-mode",
            "--quiet-output",
            str(tmp_path / "out.jsonl"),
            "--group-by",
            "skill",
        ]
    )
    assert exit_code == 2
    assert "conflicts with" in capsys.readouterr().err


def test_quiet_mode_conflicts_with_summary_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Quiet mode rejects --summary-only flag."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# S\n", encoding="utf-8")
    exit_code = main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--quiet-mode",
            "--quiet-output",
            str(tmp_path / "out.jsonl"),
            "--summary-only",
        ]
    )
    assert exit_code == 2
    assert "conflicts with" in capsys.readouterr().err


def test_quiet_mode_zero_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Quiet mode emits zero stdout bytes."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# Safe skill\n", encoding="utf-8")
    out_file = tmp_path / "quiet_out.jsonl"
    exit_code = main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--quiet-mode",
            "--quiet-output",
            str(out_file),
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_quiet_mode_writes_output_file(tmp_path: Path) -> None:
    """Quiet mode creates the output file."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# Safe skill\n", encoding="utf-8")
    out_file = tmp_path / "quiet_out.jsonl"
    exit_code = main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--quiet-mode",
            "--quiet-output",
            str(out_file),
        ]
    )
    assert exit_code == 0
    assert out_file.exists()


def test_writer_finding_records(tmp_path: Path) -> None:
    """Writer emits finding records as JSONL lines."""
    out = tmp_path / "out.jsonl"
    finding = _dummy_finding()
    result = _dummy_result(findings=(finding,))
    write_quiet_output(out_path=out, result=result, include_summary=False, include_warnings=False)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["type"] == "finding"
    assert record["version"] == "1.0.0"
    assert record["data"]["rule_id"] == "TEST_RULE"
    assert record["data"]["score"] == 55


def test_writer_warning_records(tmp_path: Path) -> None:
    """Writer emits warning records."""
    out = tmp_path / "out.jsonl"
    result = _dummy_result(warnings=("Something odd happened",))
    write_quiet_output(out_path=out, result=result, include_summary=False)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["type"] == "warning"
    assert record["data"]["message"] == "Something odd happened"


def test_writer_summary_record(tmp_path: Path) -> None:
    """Writer emits a summary record with transparency fields."""
    out = tmp_path / "out.jsonl"
    finding = _dummy_finding()
    result = _dummy_result(findings=(finding,))
    write_quiet_output(out_path=out, result=result, include_warnings=False, gate_failed=True)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    summary_line = [line for line in lines if '"type": "summary"' in line]
    assert len(summary_line) == 1
    record = json.loads(summary_line[0])
    data = record["data"]
    assert data["total_findings"] == 1
    assert data["written_findings"] == 1
    assert data["filtered_out_findings"] == 0
    assert data["gate_scope"] == "all_findings"
    assert data["gate_failed"] is True


def test_writer_min_severity_filter(tmp_path: Path) -> None:
    """Writer filters findings by min_severity but summary reflects all findings."""
    out = tmp_path / "out.jsonl"
    low = _dummy_finding(severity="low", score=20)
    high = _dummy_finding(severity="high", score=80)
    result = _dummy_result(findings=(low, high))
    write_quiet_output(out_path=out, result=result, min_severity="high")

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    finding_lines = [line for line in lines if '"type": "finding"' in line]
    assert len(finding_lines) == 1
    assert json.loads(finding_lines[0])["data"]["severity"] == "high"

    summary_line = [line for line in lines if '"type": "summary"' in line]
    data = json.loads(summary_line[0])["data"]
    assert data["total_findings"] == 2
    assert data["written_findings"] == 1
    assert data["filtered_out_findings"] == 1


def test_writer_security_only_filter(tmp_path: Path) -> None:
    """Writer filters out informational findings when security_only is set."""
    out = tmp_path / "out.jsonl"
    sec = _dummy_finding(classification="security")
    info = _dummy_finding(classification="informational")
    result = _dummy_result(findings=(sec, info))
    write_quiet_output(out_path=out, result=result, security_only=True)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    finding_lines = [line for line in lines if '"type": "finding"' in line]
    assert len(finding_lines) == 1


def test_writer_overwrite_mode(tmp_path: Path) -> None:
    """Overwrite mode replaces previous file content."""
    out = tmp_path / "out.jsonl"
    out.write_text("old content\n", encoding="utf-8")
    result = _dummy_result()
    write_quiet_output(out_path=out, result=result, include_warnings=False, write_mode="overwrite")

    content = out.read_text(encoding="utf-8")
    assert "old content" not in content


def test_writer_append_mode(tmp_path: Path) -> None:
    """Append mode adds to existing file content."""
    out = tmp_path / "out.jsonl"
    out.write_text('{"type": "finding", "existing": true}\n', encoding="utf-8")
    result = _dummy_result()
    write_quiet_output(out_path=out, result=result, include_warnings=False, write_mode="append")

    content = out.read_text(encoding="utf-8")
    assert '{"type": "finding", "existing": true}' in content
    lines = content.strip().splitlines()
    assert len(lines) >= 2


def test_writer_creates_parent_directories(tmp_path: Path) -> None:
    """Writer creates parent directories if they do not exist."""
    out = tmp_path / "nested" / "deep" / "out.jsonl"
    result = _dummy_result()
    write_quiet_output(out_path=out, result=result, include_warnings=False, include_summary=False)
    assert out.exists()


def test_writer_no_warnings_when_disabled(tmp_path: Path) -> None:
    """Writer omits warning records when include_warnings is False."""
    out = tmp_path / "out.jsonl"
    result = _dummy_result(warnings=("warn1", "warn2"))
    write_quiet_output(out_path=out, result=result, include_warnings=False, include_summary=False)

    content = out.read_text(encoding="utf-8")
    assert '"type": "warning"' not in content


def test_writer_no_summary_when_disabled(tmp_path: Path) -> None:
    """Writer omits summary record when include_summary is False."""
    out = tmp_path / "out.jsonl"
    result = _dummy_result()
    write_quiet_output(out_path=out, result=result, include_summary=False)

    content = out.read_text(encoding="utf-8")
    assert '"type": "summary"' not in content


def test_config_loads_quiet_mode_defaults(tmp_path: Path) -> None:
    """Absent quiet_mode section produces default config."""
    _write_config(tmp_path, "profile: balanced\n")
    config = load_config(tmp_path)
    assert config.quiet_mode.enabled is False
    assert config.quiet_mode.output_path is None
    assert config.quiet_mode.format == "jsonl"
    assert config.quiet_mode.write_mode == "overwrite"


def test_config_loads_quiet_mode_enabled(tmp_path: Path) -> None:
    """Config with quiet_mode.enabled: true is parsed correctly."""
    _write_config(
        tmp_path,
        "quiet_mode:\n  enabled: true\n  output_path: /tmp/out.jsonl\n  write_mode: append\n",
    )
    config = load_config(tmp_path)
    assert config.quiet_mode.enabled is True
    assert config.quiet_mode.output_path == "/tmp/out.jsonl"
    assert config.quiet_mode.write_mode == "append"


def test_config_rejects_invalid_quiet_format(tmp_path: Path) -> None:
    """Config loader raises on invalid quiet_mode.format."""
    _write_config(tmp_path, "quiet_mode:\n  format: csv\n")
    with pytest.raises(ConfigError, match="quiet_mode.format"):
        load_config(tmp_path)


def test_config_rejects_invalid_write_mode(tmp_path: Path) -> None:
    """Config loader raises on invalid quiet_mode.write_mode."""
    _write_config(tmp_path, "quiet_mode:\n  write_mode: truncate\n")
    with pytest.raises(ConfigError, match="quiet_mode.write_mode"):
        load_config(tmp_path)


def test_config_rejects_non_bool_enabled(tmp_path: Path) -> None:
    """Config loader raises when quiet_mode.enabled is not boolean."""
    _write_config(tmp_path, "quiet_mode:\n  enabled: yes_please\n")
    with pytest.raises(ConfigError, match="quiet_mode.enabled"):
        load_config(tmp_path)


def test_config_rejects_non_mapping_quiet_mode(tmp_path: Path) -> None:
    """Config loader raises when quiet_mode is not a mapping."""
    _write_config(tmp_path, "quiet_mode: true\n")
    with pytest.raises(ConfigError, match="quiet_mode must be a mapping"):
        load_config(tmp_path)


def test_validation_unknown_quiet_mode_key(tmp_path: Path) -> None:
    """Validator reports unknown keys inside quiet_mode."""
    _write_config(tmp_path, "quiet_mode:\n  unknown_key: true\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG004 and "quiet_mode" in e.field for e in errors)


def test_validation_invalid_quiet_format(tmp_path: Path) -> None:
    """Validator reports invalid quiet_mode.format value."""
    _write_config(tmp_path, "quiet_mode:\n  format: xml\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG006 and "quiet_mode.format" in e.field for e in errors)


def test_validation_invalid_quiet_write_mode(tmp_path: Path) -> None:
    """Validator reports invalid quiet_mode.write_mode value."""
    _write_config(tmp_path, "quiet_mode:\n  write_mode: delete\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG006 and "quiet_mode.write_mode" in e.field for e in errors)


def test_validation_non_bool_include_warnings(tmp_path: Path) -> None:
    """Validator reports non-boolean quiet_mode.include_warnings."""
    _write_config(tmp_path, "quiet_mode:\n  include_warnings: 1\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG005 and "include_warnings" in e.field for e in errors)


def test_validation_non_mapping_quiet_mode(tmp_path: Path) -> None:
    """Validator reports quiet_mode that is not a mapping."""
    _write_config(tmp_path, "quiet_mode: [1, 2]\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG009 and "quiet_mode" in e.field for e in errors)


def test_validation_accepts_valid_quiet_mode(tmp_path: Path) -> None:
    """Validator passes on a fully valid quiet_mode block."""
    _write_config(
        tmp_path,
        "quiet_mode:\n  enabled: true\n  output_path: out.jsonl\n"
        "  format: jsonl\n  include_warnings: false\n"
        "  include_summary: true\n  write_mode: append\n",
    )
    errors = validate_config_file(tmp_path)
    assert not any("quiet_mode" in e.field for e in errors)


def test_quiet_mode_config_fallback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Quiet mode enabled via config with output_path works end-to-end."""
    out_file = tmp_path / "quiet_out.jsonl"
    _write_config(
        tmp_path,
        f"quiet_mode:\n  enabled: true\n  output_path: {out_file}\n",
    )
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# Safe\n", encoding="utf-8")
    exit_code = main(["scan", "--root", str(tmp_path)])
    assert exit_code == 0
    assert out_file.exists()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "record_type",
    [
        pytest.param("finding", id="finding-record"),
        pytest.param("warning", id="warning-record"),
        pytest.param("summary", id="summary-record"),
    ],
)
def test_quiet_record_has_envelope_fields(tmp_path: Path, record_type: str) -> None:
    """Each JSONL record has type, version, timestamp, and data fields."""
    out = tmp_path / "out.jsonl"
    finding = _dummy_finding()
    result = _dummy_result(findings=(finding,), warnings=("test warning",))
    write_quiet_output(out_path=out, result=result)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    records_of_type = [json.loads(line) for line in lines if f'"type": "{record_type}"' in line]
    assert len(records_of_type) >= 1
    record = records_of_type[0]
    assert "type" in record
    assert "version" in record
    assert "timestamp" in record
    assert "data" in record
    assert record["type"] == record_type


def test_quiet_mode_gate_evaluates_all_findings(tmp_path: Path) -> None:
    """Gate (--fail-on) evaluates all findings, not just filtered output."""
    skill_dir = tmp_path / "skills" / "risky"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: risky\n---\n# Risky\nwebhook: http://192.168.1.20/hook\ntoken: ${API_TOKEN}\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "out.jsonl"
    exit_code = main(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--quiet-mode",
            "--quiet-output",
            str(out_file),
            "--fail-on",
            "low",
            "--min-severity",
            "high",
        ]
    )
    assert exit_code == 1


def test_quiet_summary_gate_scope_field(tmp_path: Path) -> None:
    """Summary record includes gate_scope: all_findings."""
    out = tmp_path / "out.jsonl"
    result = _dummy_result(findings=(_dummy_finding(),))
    write_quiet_output(out_path=out, result=result, gate_failed=False)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    summary = json.loads([line for line in lines if '"type": "summary"' in line][0])
    assert summary["data"]["gate_scope"] == "all_findings"


def test_cli_quiet_mode_respects_config_include_summary(tmp_path: Path) -> None:
    """CLI --quiet-mode loads include_summary setting from config."""
    out_file = tmp_path / "out.jsonl"
    _write_config(
        tmp_path,
        f"quiet_mode:\n  enabled: true\n  output_path: {out_file}\n  include_summary: false\n",
    )
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# Safe\n", encoding="utf-8")
    exit_code = main(["scan", "--root", str(tmp_path), "--quiet-mode", "--quiet-output", str(out_file)])
    assert exit_code == 0
    content = out_file.read_text(encoding="utf-8")
    assert '"type": "summary"' not in content


def test_cli_quiet_mode_respects_config_write_mode(tmp_path: Path) -> None:
    """CLI --quiet-mode loads write_mode setting from config."""
    out_file = tmp_path / "out.jsonl"
    out_file.write_text('{"existing": true}\n', encoding="utf-8")
    _write_config(
        tmp_path,
        f"quiet_mode:\n  enabled: true\n  output_path: {out_file}\n  write_mode: append\n",
    )
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# Safe\n", encoding="utf-8")
    exit_code = main(["scan", "--root", str(tmp_path), "--quiet-mode", "--quiet-output", str(out_file)])
    assert exit_code == 0
    content = out_file.read_text(encoding="utf-8")
    assert '{"existing": true}' in content


def test_config_rejects_enabled_without_output_path(tmp_path: Path) -> None:
    """Config loader raises when quiet_mode.enabled is true but output_path is missing."""
    _write_config(tmp_path, "quiet_mode:\n  enabled: true\n")
    with pytest.raises(ConfigError, match="output_path"):
        load_config(tmp_path)


def test_validation_enabled_without_output_path(tmp_path: Path) -> None:
    """Validator reports quiet_mode.enabled without output_path."""
    _write_config(tmp_path, "quiet_mode:\n  enabled: true\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG011 and "output_path" in e.message for e in errors)


def test_quiet_output_implies_quiet_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--quiet-output without --quiet-mode enables quiet mode."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: s\n---\n# Safe\n", encoding="utf-8")
    out_file = tmp_path / "quiet_out.jsonl"
    exit_code = main(["scan", "--root", str(tmp_path), "--quiet-output", str(out_file)])
    assert exit_code == 0
    assert out_file.exists()
    assert capsys.readouterr().out == ""
