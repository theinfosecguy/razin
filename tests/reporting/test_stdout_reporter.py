"""Tests for rich stdout reporter."""

from __future__ import annotations

import pytest

from razin.constants.reporting import ANSI_GREEN, ANSI_RED, ANSI_RESET, ANSI_YELLOW
from razin.model import Evidence, Finding, ScanResult
from razin.reporting.stdout import StdoutReporter
from razin.types import Severity


def _make_finding(
    *,
    skill: str = "test-skill",
    rule_id: str = "NET_RAW_IP",
    score: int = 80,
    severity: Severity = "high",
    finding_id: str = "abc123",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        score=score,
        confidence="high",
        title=f"Test {rule_id}",
        description="Test description",
        evidence=Evidence(path="SKILL.md", line=1, snippet="test"),
        skill=skill,
        rule_id=rule_id,
        recommendation="Fix it",
    )


def _make_result(
    *,
    scanned_files: int = 5,
    total_findings: int = 10,
    aggregate_score: int = 75,
    aggregate_severity: Severity = "high",
    counts: dict[Severity, int] | None = None,
    findings: list[Finding] | None = None,
    duration: float = 1.234,
    cache_hits: int = 2,
    cache_misses: int = 3,
    high_severity_min: int = 70,
    medium_severity_min: int = 40,
    aggregate_min_rule_score: int = 40,
) -> ScanResult:
    resolved_counts: dict[Severity, int] = {"high": 3, "medium": 4, "low": 3} if counts is None else counts

    return ScanResult(
        scanned_files=scanned_files,
        total_findings=total_findings,
        aggregate_score=aggregate_score,
        aggregate_severity=aggregate_severity,
        counts_by_severity=resolved_counts,
        findings=tuple(findings or []),
        duration_seconds=duration,
        warnings=(),
        cache_hits=cache_hits,
        cache_misses=cache_misses,
        high_severity_min=high_severity_min,
        medium_severity_min=medium_severity_min,
        aggregate_min_rule_score=aggregate_min_rule_score,
    )


def test_header_contains_summary_title() -> None:
    result = _make_result()
    output = StdoutReporter(result, color=False).render()
    assert ">_ RAZIN" in output
    assert "// static analysis for LLM skills" in output
    assert "Scan summary" in output


def test_header_shows_risk_score() -> None:
    result = _make_result(aggregate_score=94, aggregate_severity="high")
    output = StdoutReporter(result, color=False).render()
    assert "Risk Score" in output
    assert "94" in output
    assert "high" in output


def test_header_shows_file_count() -> None:
    result = _make_result(scanned_files=42)
    output = StdoutReporter(result, color=False).render()
    assert "42" in output


def test_header_shows_finding_count() -> None:
    result = _make_result(total_findings=15)
    output = StdoutReporter(result, color=False).render()
    assert "15" in output


def test_header_shows_duration() -> None:
    result = _make_result(duration=2.567)
    output = StdoutReporter(result, color=False).render()
    assert "2.567s" in output


def test_header_shows_inline_severity_breakdown() -> None:
    result = _make_result(counts={"high": 1, "medium": 26, "low": 4})
    output = StdoutReporter(result, color=False).render()
    assert "1 high" in output
    assert "26 medium" in output
    assert "4 low" in output


def test_cache_hidden_by_default() -> None:
    result = _make_result(cache_hits=10, cache_misses=5)
    output = StdoutReporter(result, color=False).render()
    assert "hits" not in output


def test_cache_shown_in_verbose() -> None:
    result = _make_result(cache_hits=10, cache_misses=5)
    output = StdoutReporter(result, color=False, verbose=True).render()
    assert "10" in output
    assert "hits" in output
    assert "5" in output
    assert "misses" in output


def test_header_has_separator_line() -> None:
    result = _make_result()
    output = StdoutReporter(result, color=False).render()
    assert "\u2500" in output


def test_findings_table_has_borders() -> None:
    findings = [
        _make_finding(skill="evil-skill", rule_id="SECRET_REF", score=90),
    ]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False).render()
    assert "┌" in output
    assert "┬" in output
    assert "┼" in output
    assert "┴" in output
    assert "└" in output
    assert "│" in output


def test_findings_table_shows_all_findings() -> None:
    all_findings = [
        _make_finding(skill="evil-skill", rule_id="SECRET_REF", score=90),
        _make_finding(skill="risky-skill", rule_id="NET_RAW_IP", score=80, finding_id="def456"),
    ]
    result = _make_result(findings=all_findings)
    output = StdoutReporter(result, color=False).render()
    assert "Findings" in output
    assert "evil-skill" in output
    assert "SECRET_REF" in output
    assert "90" in output


def test_findings_table_hidden_when_empty() -> None:
    result = _make_result(findings=[])
    output = StdoutReporter(result, color=False).render()
    # The section title line; "Findings: N" in the header is separate
    assert "\n  Findings\n" not in output


@pytest.mark.parametrize(
    ("severity", "score", "finding_id", "expected_color"),
    [
        ("high", 80, "abc123", ANSI_RED),
        ("medium", 55, "med1", ANSI_YELLOW),
        ("low", 20, "low1", ANSI_GREEN),
    ],
    ids=["high-red", "medium-yellow", "low-green"],
)
def test_severity_colored_correctly(severity: Severity, score: int, finding_id: str, expected_color: str) -> None:
    f = [_make_finding(severity=severity, score=score, finding_id=finding_id)]
    result = _make_result(findings=f)
    output = StdoutReporter(result, color=True).render()
    assert expected_color in output


@pytest.mark.parametrize(
    ("score", "severity", "finding_id", "expected_color"),
    [
        (85, "high", "abc123", ANSI_RED),
        (50, "medium", "m1", ANSI_YELLOW),
        (20, "low", "l1", ANSI_GREEN),
    ],
    ids=["high-red", "medium-yellow", "low-green"],
)
def test_score_colored_correctly(score: int, severity: Severity, finding_id: str, expected_color: str) -> None:
    f = [_make_finding(score=score, severity=severity, finding_id=finding_id)]
    result = _make_result(findings=f)
    output = StdoutReporter(result, color=True).render()
    assert f"{expected_color}{score}{ANSI_RESET}" in output


def test_color_disabled_produces_no_ansi() -> None:
    f = [_make_finding(score=85)]
    result = _make_result(findings=f, counts={"high": 1, "medium": 0, "low": 0})
    output = StdoutReporter(result, color=False).render()
    assert "\033[" not in output


def test_risk_score_colored_in_header() -> None:
    result = _make_result(aggregate_score=94, aggregate_severity="high")
    output = StdoutReporter(result, color=True).render()
    assert ANSI_RED in output


def test_render_is_deterministic() -> None:
    """Same input always produces same output."""
    findings = [
        _make_finding(skill="a-skill", rule_id="NET_RAW_IP", score=80, finding_id="aaa"),
        _make_finding(skill="b-skill", rule_id="SECRET_REF", score=70, finding_id="bbb"),
    ]
    result = _make_result(
        findings=findings,
        duration=1.000,
    )

    first = StdoutReporter(result).render()
    second = StdoutReporter(result).render()
    assert first == second


def test_golden_snapshot_no_color() -> None:
    """Golden snapshot test for stable formatting (no color)."""
    findings = [
        _make_finding(skill="risky-skill", rule_id="NET_RAW_IP", score=85, finding_id="f01"),
        _make_finding(skill="risky-skill", rule_id="SECRET_REF", score=75, finding_id="f02"),
    ]
    result = ScanResult(
        scanned_files=3,
        total_findings=6,
        aggregate_score=94,
        aggregate_severity="high",
        counts_by_severity={"high": 2, "medium": 2, "low": 2},
        findings=tuple(findings),
        duration_seconds=0.500,
        warnings=(),
        cache_hits=1,
        cache_misses=2,
    )

    output = StdoutReporter(result, color=False).render()

    # Verify header content
    assert ">_ RAZIN" in output
    assert "// static analysis for LLM skills" in output
    assert "Scan summary" in output
    assert "─" in output  # separator line
    assert "Risk Score" in output
    assert "94" in output
    assert "high" in output
    assert "3" in output  # Files
    assert "6" in output  # Findings
    assert "0.500s" in output
    assert "2 high" in output
    assert "2 medium" in output
    assert "2 low" in output

    # Cache hidden by default
    assert "hits" not in output

    # Verbose shows cache
    verbose_output = StdoutReporter(result, color=False, verbose=True).render()
    assert "hits" in verbose_output

    # Findings table present
    assert "Findings" in output
    assert "risky-skill" in output
    assert "NET_RAW_IP" in output

    # Verify table borders with proper intersections
    assert "┌" in output
    assert "┬" in output
    assert "│" in output
    assert "┼" in output
    assert "┴" in output
    assert "└" in output

    # Verify removed sections are absent
    assert "Per-Skill Findings" not in output
    assert "Rule Distribution" not in output
    assert "█" not in output  # no histogram bars

    # No ANSI escapes in no-color mode
    assert "\033[" not in output


def test_grouped_by_skill_shows_group_headers() -> None:
    """Two skills with findings produce both [skill-name] headers."""
    findings = [
        _make_finding(skill="alpha-skill", rule_id="NET_RAW_IP", score=80, finding_id="a1"),
        _make_finding(skill="beta-skill", rule_id="SECRET_REF", score=60, severity="medium", finding_id="b1"),
    ]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False, group_by="skill").render()
    assert "[alpha-skill]" in output
    assert "[beta-skill]" in output
    assert "grouped by skill" in output


def test_grouped_by_rule_shows_group_headers() -> None:
    """Two rules produce both [RULE_ID] headers."""
    findings = [
        _make_finding(skill="s1", rule_id="NET_RAW_IP", score=80, finding_id="a1"),
        _make_finding(skill="s2", rule_id="SECRET_REF", score=60, severity="medium", finding_id="b1"),
    ]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False, group_by="rule").render()
    assert "[NET_RAW_IP]" in output
    assert "[SECRET_REF]" in output
    assert "grouped by rule" in output


def test_grouped_no_findings_produces_no_table() -> None:
    """Empty findings produce no grouped table section."""
    result = _make_result(findings=[])
    output = StdoutReporter(result, color=False, group_by="skill").render()
    assert "grouped" not in output


def test_grouped_default_is_flat_table() -> None:
    """group_by=None renders the flat table with column headers, not grouped."""
    findings = [_make_finding(score=80)]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False, group_by=None).render()
    assert "Skill" in output
    assert "grouped" not in output


def test_grouped_by_skill_no_color() -> None:
    """color=False produces no ANSI escape sequences in grouped output."""
    findings = [
        _make_finding(skill="s1", rule_id="NET_RAW_IP", score=80, finding_id="a1"),
    ]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False, group_by="skill").render()
    assert "\033[" not in output


def test_grouped_by_skill_shows_per_group_score() -> None:
    """Group header contains score=, severity=, and findings=N."""
    findings = [
        _make_finding(skill="s1", rule_id="NET_RAW_IP", score=80, finding_id="a1"),
        _make_finding(skill="s1", rule_id="SECRET_REF", score=50, severity="medium", finding_id="a2"),
    ]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False, group_by="skill").render()
    assert "score=" in output
    assert "severity=" in output
    assert "findings=2" in output


def test_grouped_sorts_by_risk_descending() -> None:
    """Group with highest score appears before group with lower score."""
    findings = [
        _make_finding(skill="low-risk", rule_id="NET_RAW_IP", score=30, severity="low", finding_id="l1"),
        _make_finding(skill="high-risk", rule_id="SECRET_REF", score=80, finding_id="h1"),
    ]
    result = _make_result(findings=findings)
    output = StdoutReporter(result, color=False, group_by="skill").render()
    high_pos = output.index("[high-risk]")
    low_pos = output.index("[low-risk]")
    assert high_pos < low_pos


def test_grouped_severity_uses_profile_thresholds() -> None:
    """Profile thresholds from ScanResult determine grouped header severity label."""
    findings = [
        _make_finding(skill="s1", rule_id="MCP_ENDPOINT", score=70, severity="medium", finding_id="m1"),
    ]
    # Balanced profile thresholds (high>=80) label score 70 as medium.
    result = _make_result(
        findings=findings,
        high_severity_min=80,
        medium_severity_min=50,
    )
    output = StdoutReporter(
        result,
        color=False,
        group_by="skill",
    ).render()
    assert "severity=medium" in output
    assert "severity=high" not in output
