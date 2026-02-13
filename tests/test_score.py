"""Tests for scoring and severity helpers."""

from __future__ import annotations

from razin.model import Evidence, Finding
from razin.scanner.score import aggregate_overall_score, severity_counts, severity_from_score
from razin.types import Severity


def _finding(
    score: int,
    rule_id: str = "R",
    *,
    path: str = "a.yaml",
    line: int = 1,
) -> Finding:
    severity: Severity = "high" if score >= 70 else ("medium" if score >= 40 else "low")
    return Finding(
        id=f"id-{rule_id}-{score}-{line}",
        severity=severity,
        score=score,
        confidence="high",
        title="t",
        description="d",
        evidence=Evidence(path=path, line=line, snippet="x"),
        skill="s",
        rule_id=rule_id,
        recommendation="r",
    )


def test_severity_from_score_boundaries() -> None:
    assert severity_from_score(0) == "low"
    assert severity_from_score(39) == "low"
    assert severity_from_score(40) == "medium"
    assert severity_from_score(69) == "medium"
    assert severity_from_score(70) == "high"


def test_aggregate_overall_score_increases_with_more_findings() -> None:
    low = aggregate_overall_score([_finding(20)])
    mixed = aggregate_overall_score([_finding(20), _finding(60)])

    assert mixed > low


def test_severity_counts_has_stable_keys() -> None:
    counts = severity_counts([_finding(70), _finding(50)])

    assert counts == {"high": 1, "medium": 1, "low": 0}


class TestScoringDampening:
    """Aggregate scoring should use per-rule max, not per-finding."""

    def test_multiple_findings_same_rule_use_max(self) -> None:
        """10 findings from TOOL_INVOCATION should aggregate like 1."""
        single = aggregate_overall_score([_finding(62, "TOOL_INVOCATION")])
        many = aggregate_overall_score([_finding(62, "TOOL_INVOCATION", line=i) for i in range(10)])
        assert single == many

    def test_different_rules_combine(self) -> None:
        """Findings from different rules should all contribute."""
        one_rule = aggregate_overall_score([_finding(60, "RULE_A")])
        two_rules = aggregate_overall_score([_finding(60, "RULE_A"), _finding(50, "RULE_B")])
        assert two_rules > one_rule

    def test_score_does_not_saturate_with_few_medium_findings(self) -> None:
        """A skill with 5 medium-score findings from different rules shouldn't hit 100."""
        findings = [
            _finding(20, "TOOL_INVOCATION"),
            _finding(35, "NET_UNKNOWN_DOMAIN"),
            _finding(12, "EXTERNAL_URLS"),
            _finding(15, "DYNAMIC_SCHEMA"),
            _finding(28, "MCP_REQUIRED"),
        ]
        score = aggregate_overall_score(findings)
        assert score < 100, f"Score {score} should be < 100"

    def test_high_risk_skill_still_scores_high(self) -> None:
        """A skill with genuinely diverse high-risk signals should score high."""
        findings = [
            _finding(82, "NET_RAW_IP"),
            _finding(74, "SECRET_REF"),
            _finding(72, "EXEC_FIELDS"),
            _finding(90, "MCP_DENYLIST"),
            _finding(76, "TYPOSQUAT"),
        ]
        score = aggregate_overall_score(findings)
        assert score >= 90, f"Score {score} should be >= 90 for high-risk"

    def test_empty_findings_is_zero(self) -> None:
        assert aggregate_overall_score([]) == 0


class TestProfileAwareScoring:
    """aggregate_overall_score min_rule_score parameter controls profile behavior."""

    def test_strict_includes_low_score_rules(self) -> None:
        """With strict min_rule_score=20, a 25-score finding contributes."""
        findings = [_finding(25, "TOOL_INVOCATION"), _finding(70, "MCP_ENDPOINT")]
        strict = aggregate_overall_score(findings, min_rule_score=20)
        balanced = aggregate_overall_score(findings, min_rule_score=40)
        # Strict includes the 25 finding, balanced does not → strict >= balanced
        assert strict >= balanced

    def test_audit_returns_max_rule_score(self) -> None:
        """With audit min_rule_score=101, nothing is significant → returns max."""
        findings = [_finding(70, "MCP_ENDPOINT"), _finding(45, "AUTH_CONNECTION")]
        score = aggregate_overall_score(findings, min_rule_score=101)
        # Falls back to max per-rule score
        assert score == 70

    def test_balanced_context_signals_excluded(self) -> None:
        """Under balanced (min_rule_score=40), score-20 signals don't inflate."""
        findings = [
            _finding(20, "TOOL_INVOCATION"),
            _finding(15, "DYNAMIC_SCHEMA"),
            _finding(12, "EXTERNAL_URLS"),
        ]
        score = aggregate_overall_score(findings, min_rule_score=40)
        # All below threshold → returns max (20)
        assert score == 20
