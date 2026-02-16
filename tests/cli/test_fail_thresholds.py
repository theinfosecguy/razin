"""Tests for CI exit-code gating via --fail-on and --fail-on-score."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal
from unittest.mock import MagicMock, patch

import pytest

from razin.cli.handlers import evaluate_fail_thresholds
from razin.cli.main import build_parser, main
from razin.model import Evidence, Finding, ScanResult


def _empty_result(**overrides: Any) -> ScanResult:
    """Build a minimal ScanResult with sensible defaults."""
    defaults: dict[str, Any] = {
        "scanned_files": 1,
        "total_findings": 0,
        "aggregate_score": 0,
        "aggregate_severity": "low",
        "counts_by_severity": {"high": 0, "medium": 0, "low": 0},
        "findings": (),
        "duration_seconds": 0.1,
        "warnings": (),
        "cache_hits": 0,
        "cache_misses": 1,
    }
    defaults.update(overrides)
    return ScanResult(**defaults)


def _make_finding(
    *,
    severity: Literal["low", "medium", "high"] = "high",
    score: int = 80,
    rule_id: str = "NET_RAW_IP",
) -> Finding:
    """Build a minimal Finding."""
    return Finding(
        id="test-id",
        severity=severity,
        score=score,
        confidence="high",
        title=f"Test {rule_id}",
        description="desc",
        evidence=Evidence(path="SKILL.md", line=1, snippet="x"),
        skill="test-skill",
        rule_id=rule_id,
        recommendation="Fix it",
    )


def test_build_parser_fail_on_accepts_valid_choices(tmp_path: Path) -> None:
    """--fail-on accepts high, medium, and low."""
    parser = build_parser()
    for level in ("high", "medium", "low"):
        args = parser.parse_args(["scan", "--root", str(tmp_path), "--fail-on", level])
        assert args.fail_on == level


def test_build_parser_fail_on_defaults_none(tmp_path: Path) -> None:
    """--fail-on and --fail-on-score default to None when omitted."""
    parser = build_parser()
    args = parser.parse_args(["scan", "--root", str(tmp_path)])
    assert args.fail_on is None
    assert args.fail_on_score is None


def test_build_parser_fail_on_score_parses_int(tmp_path: Path) -> None:
    """--fail-on-score parses an integer threshold."""
    parser = build_parser()
    args = parser.parse_args(["scan", "--root", str(tmp_path), "--fail-on-score", "70"])
    assert args.fail_on_score == 70


def test_build_parser_fail_on_rejects_invalid_choice() -> None:
    """--fail-on critical is rejected by argparse."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--root", ".", "--fail-on", "critical"])


def test_evaluate_fail_on_high_returns_1_when_high_finding() -> None:
    """Exit 1 when --fail-on high and a high finding exists."""
    result = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="high"),),
    )
    assert evaluate_fail_thresholds(result, fail_on="high", fail_on_score=None) == 1


def test_evaluate_fail_on_high_returns_0_when_only_medium() -> None:
    """Exit 0 when --fail-on high and only medium findings exist."""
    result = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="medium", score=50),),
    )
    assert evaluate_fail_thresholds(result, fail_on="high", fail_on_score=None) == 0


def test_evaluate_fail_on_medium_catches_medium() -> None:
    """Exit 1 when --fail-on medium and a medium finding exists."""
    result = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="medium", score=50),),
    )
    assert evaluate_fail_thresholds(result, fail_on="medium", fail_on_score=None) == 1


def test_evaluate_fail_on_medium_catches_high() -> None:
    """Exit 1 when --fail-on medium and a high finding exists."""
    result = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="high"),),
    )
    assert evaluate_fail_thresholds(result, fail_on="medium", fail_on_score=None) == 1


def test_evaluate_fail_on_low_catches_any_finding() -> None:
    """Exit 1 when --fail-on low and any finding exists (zero-tolerance)."""
    result = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="low", score=20),),
    )
    assert evaluate_fail_thresholds(result, fail_on="low", fail_on_score=None) == 1


def test_evaluate_fail_on_score_returns_1_above_threshold() -> None:
    """Exit 1 when aggregate score meets the threshold."""
    result = _empty_result(aggregate_score=75)
    assert evaluate_fail_thresholds(result, fail_on=None, fail_on_score=70) == 1


def test_evaluate_fail_on_score_returns_0_below_threshold() -> None:
    """Exit 0 when aggregate score is below the threshold."""
    result = _empty_result(aggregate_score=30)
    assert evaluate_fail_thresholds(result, fail_on=None, fail_on_score=70) == 0


def test_evaluate_no_fail_flags_returns_0() -> None:
    """Exit 0 when neither fail flag is set, even with high findings."""
    result = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="high"),),
    )
    assert evaluate_fail_thresholds(result, fail_on=None, fail_on_score=None) == 0


def test_evaluate_both_flags_either_triggers() -> None:
    """Either condition triggers exit 1 when both flags are set (logical OR)."""
    high_result = _empty_result(
        total_findings=1,
        aggregate_score=30,
        findings=(_make_finding(severity="high"),),
    )
    assert evaluate_fail_thresholds(high_result, fail_on="high", fail_on_score=90) == 1

    score_result = _empty_result(aggregate_score=95)
    assert evaluate_fail_thresholds(score_result, fail_on="high", fail_on_score=90) == 1


def test_fail_on_score_out_of_range(capsys: pytest.CaptureFixture[str]) -> None:
    """--fail-on-score 150 returns exit 2 (validation error)."""
    code = main(["scan", "--root", ".", "--fail-on-score", "150", "--no-stdout"])
    captured = capsys.readouterr()
    assert code == 2
    assert "--fail-on-score must be between 0 and 100" in captured.err


def test_fail_on_score_negative_out_of_range(capsys: pytest.CaptureFixture[str]) -> None:
    """--fail-on-score -1 returns exit 2 (validation error)."""
    code = main(["scan", "--root", ".", "--fail-on-score", "-1", "--no-stdout"])
    captured = capsys.readouterr()
    assert code == 2
    assert "--fail-on-score must be between 0 and 100" in captured.err


@patch("razin.cli.main.scan_workspace")
def test_main_fail_on_high_returns_1(mock_scan: MagicMock) -> None:
    """main() returns 1 when --fail-on high and high findings present."""
    mock_scan.return_value = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="high"),),
    )
    code = main(["scan", "--root", ".", "--fail-on", "high", "--no-stdout"])
    assert code == 1


@patch("razin.cli.main.scan_workspace")
def test_main_fail_on_high_returns_0_when_clean(mock_scan: MagicMock) -> None:
    """main() returns 0 when --fail-on high and no findings."""
    mock_scan.return_value = _empty_result()
    code = main(["scan", "--root", ".", "--fail-on", "high", "--no-stdout"])
    assert code == 0


@patch("razin.cli.main.scan_workspace")
def test_main_no_fail_flags_returns_0(mock_scan: MagicMock) -> None:
    """main() returns 0 when no fail flags, backward compatible."""
    mock_scan.return_value = _empty_result(
        total_findings=1,
        findings=(_make_finding(severity="high"),),
    )
    code = main(["scan", "--root", ".", "--no-stdout"])
    assert code == 0
