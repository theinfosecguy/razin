"""Tests for CLI parser and main behavior."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from razin.cli.main import build_parser, main
from razin.exceptions import ConfigError
from razin.model import ScanResult


def test_build_parser_accepts_scan_flags(tmp_path: Path) -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--mcp-allowlist",
            "rube.app",
        ]
    )

    assert args.command == "scan"
    assert args.root == tmp_path
    assert args.output_dir == tmp_path / "out"
    assert args.mcp_allowlist == ["rube.app"]


def test_build_parser_output_dir_optional(tmp_path: Path) -> None:
    parser = build_parser()

    args = parser.parse_args(["scan", "--root", str(tmp_path)])

    assert args.output_dir is None


def test_build_parser_no_stdout_flag(tmp_path: Path) -> None:
    parser = build_parser()

    args = parser.parse_args(["scan", "--root", str(tmp_path), "--no-stdout"])

    assert args.no_stdout is True


def test_build_parser_output_format_flag(tmp_path: Path) -> None:
    parser = build_parser()

    args = parser.parse_args(["scan", "--root", str(tmp_path), "--output-format", "json"])

    assert args.output_format == "json"


def test_build_parser_rules_dir_flag(tmp_path: Path) -> None:
    parser = build_parser()

    args = parser.parse_args(["scan", "--root", str(tmp_path), "--rules-dir", str(tmp_path / "rules")])

    assert args.rules_dir == tmp_path / "rules"
    assert args.rule_file is None


def test_build_parser_rule_file_repeatable(tmp_path: Path) -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--root",
            str(tmp_path),
            "--rule-file",
            str(tmp_path / "a.yaml"),
            "--rule-file",
            str(tmp_path / "b.yaml"),
        ]
    )

    assert args.rules_dir is None
    assert args.rule_file == [tmp_path / "a.yaml", tmp_path / "b.yaml"]


def test_build_parser_rejects_conflicting_rule_sources(tmp_path: Path) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "scan",
                "--root",
                str(tmp_path),
                "--rules-dir",
                str(tmp_path / "rules"),
                "--rule-file",
                str(tmp_path / "a.yaml"),
            ]
        )


def test_build_parser_help_includes_ascii_banner() -> None:
    parser = build_parser()
    help_text = parser.format_help()

    assert ">_ RAZIN" in help_text
    assert "// static analysis for LLM skills" in help_text


@patch("razin.cli.main.scan_workspace", side_effect=ConfigError("bad config"))
def test_main_returns_config_error_code(mock_scan: MagicMock) -> None:
    code = main(["scan", "--root", "."])

    assert code == 2


def test_main_help_shows_ascii_banner(capsys) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(SystemExit) as exc_info:
        main(["-h"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert ">_ RAZIN" in captured.out
    assert "// static analysis for LLM skills" in captured.out


@patch(
    "razin.cli.main.scan_workspace",
    return_value=ScanResult(
        scanned_files=1,
        total_findings=0,
        aggregate_score=0,
        aggregate_severity="low",
        counts_by_severity={"high": 0, "medium": 0, "low": 0},
        findings=(),
        duration_seconds=0.1,
        warnings=(),
        cache_hits=0,
        cache_misses=1,
    ),
)
def test_main_success_prints_rich_summary(mock_scan: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--root", "."])
    captured = capsys.readouterr()

    assert code == 0
    assert ">_ RAZIN" in captured.out
    assert "Scan summary" in captured.out
    assert "1" in captured.out


@patch(
    "razin.cli.main.scan_workspace",
    return_value=ScanResult(
        scanned_files=1,
        total_findings=0,
        aggregate_score=0,
        aggregate_severity="low",
        counts_by_severity={"high": 0, "medium": 0, "low": 0},
        findings=(),
        duration_seconds=0.1,
        warnings=(),
        cache_hits=0,
        cache_misses=1,
    ),
)
def test_main_no_stdout_flag(mock_scan: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--root", ".", "--no-stdout"])
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out == ""


@patch("razin.cli.main.scan_workspace")
def test_main_passes_rule_source_arguments(mock_scan: MagicMock) -> None:
    mock_scan.return_value = ScanResult(
        scanned_files=0,
        total_findings=0,
        aggregate_score=0,
        aggregate_severity="low",
        counts_by_severity={"high": 0, "medium": 0, "low": 0},
        findings=(),
        duration_seconds=0.0,
        warnings=(),
        cache_hits=0,
        cache_misses=0,
    )

    code = main(
        [
            "scan",
            "--root",
            ".",
            "--rule-file",
            "a.yaml",
            "--rule-file",
            "b.yaml",
            "--no-stdout",
        ]
    )

    assert code == 0
    call_kwargs = mock_scan.call_args[1]
    assert call_kwargs["rules_dir"] is None
    assert call_kwargs["rule_files"] == (Path("a.yaml"), Path("b.yaml"))
