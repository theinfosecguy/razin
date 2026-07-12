"""Tests for scoring and severity helpers."""

from __future__ import annotations

import pytest

from razin.model import Evidence, Finding
from razin.scanner.assessment import signal_kind_for_rule
from razin.scanner.score import aggregate_overall_score, severity_counts, severity_from_score, sorted_top_risks
from razin.types import Severity


def _finding(
    score: int,
    rule_id: str = "R",
    *,
    path: str = "a.yaml",
    line: int = 1,
) -> Finding:
    severity: Severity = "high" if score >= 70 else ("medium" if score >= 40 else "low")
    signal_kind = signal_kind_for_rule(rule_id)
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
        classification=("informational" if signal_kind == "capability" else "security"),
        signal_kind=signal_kind,
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (39, "low"),
        (40, "medium"),
        (69, "medium"),
        (70, "high"),
    ],
)
def test_severity_from_score_boundaries(score: int, expected: str) -> None:
    assert severity_from_score(score) == expected


def test_aggregate_overall_score_increases_with_more_findings() -> None:
    low = aggregate_overall_score([_finding(20)])
    mixed = aggregate_overall_score([_finding(20), _finding(60)])

    assert mixed > low


def test_severity_counts_has_stable_keys() -> None:
    counts = severity_counts([_finding(70), _finding(50)])

    assert counts == {"high": 1, "medium": 1, "low": 0}


def test_multiple_findings_same_rule_use_max() -> None:
    """10 findings from TOOL_INVOCATION should aggregate like 1."""
    single = aggregate_overall_score([_finding(62, "TOOL_INVOCATION")])
    many = aggregate_overall_score([_finding(62, "TOOL_INVOCATION", line=i) for i in range(10)])
    assert single == many


def test_different_rules_do_not_combine_as_probabilities() -> None:
    """Correlated detector weights must not inflate review priority."""
    one_rule = aggregate_overall_score([_finding(60, "RULE_A")])
    two_rules = aggregate_overall_score([_finding(60, "RULE_A"), _finding(50, "RULE_B")])
    assert two_rules == one_rule


def test_equal_strong_scores_remain_a_single_priority() -> None:
    """Two attack-chain findings remain priority 80 rather than saturating."""
    one = _finding(80, "PACKAGE_DATA_EXFILTRATION")
    two = _finding(80, "PACKAGE_REMOTE_CODE_EXECUTION")
    one_rule = aggregate_overall_score([one])
    two_rules = aggregate_overall_score([one, two])

    assert one_rule == 80
    assert two_rules == 80


def test_score_does_not_saturate_with_few_medium_findings() -> None:
    """A skill with 5 medium-score findings from different rules shouldn't hit 100."""
    findings = [
        _finding(20, "TOOL_INVOCATION"),
        _finding(35, "NET_UNKNOWN_DOMAIN"),
        _finding(15, "DYNAMIC_SCHEMA"),
        _finding(15, "NET_DOC_DOMAIN"),
        _finding(28, "MCP_REQUIRED"),
    ]
    score = aggregate_overall_score(findings)
    assert score < 100, f"Score {score} should be < 100"


def test_diverse_ambiguous_signals_do_not_create_high_priority() -> None:
    """Capabilities and policy-review findings cannot combine into a high claim."""
    findings = [
        _finding(82, "NET_RAW_IP"),
        _finding(74, "SECRET_REF"),
        _finding(72, "EXEC_FIELDS"),
        _finding(90, "MCP_DENYLIST"),
        _finding(76, "TYPOSQUAT"),
    ]
    score = aggregate_overall_score(findings)
    assert score == 69


def test_empty_findings_is_zero() -> None:
    assert aggregate_overall_score([]) == 0


def test_legacy_min_rule_score_does_not_change_priority() -> None:
    """Legacy aggregate thresholds no longer alter review priority."""
    findings = [_finding(25, "TOOL_INVOCATION"), _finding(70, "MCP_ENDPOINT")]
    strict = aggregate_overall_score(findings, min_rule_score=20)
    balanced = aggregate_overall_score(findings, min_rule_score=40)
    # Strict includes the 25 finding, balanced does not → strict >= balanced
    assert strict >= balanced


def test_legacy_audit_threshold_is_ignored() -> None:
    """The removed probabilistic threshold remains accepted only for compatibility."""
    findings = [_finding(70, "MCP_ENDPOINT"), _finding(45, "AUTH_CONNECTION")]
    score = aggregate_overall_score(findings, min_rule_score=101)
    assert score == aggregate_overall_score(findings)


def test_balanced_context_signals_excluded() -> None:
    """Under balanced (min_rule_score=40), score-20 signals don't inflate."""
    findings = [
        _finding(20, "TOOL_INVOCATION"),
        _finding(15, "DYNAMIC_SCHEMA"),
        _finding(15, "NET_DOC_DOMAIN"),
    ]
    score = aggregate_overall_score(findings, min_rule_score=40)
    assert score == 0


def test_top_risks_prioritizes_actionable_evidence_over_capability_weight() -> None:
    capability = _finding(99, "SECRET_REF")
    actionable = _finding(50, "PROMPT_INJECTION")

    assert sorted_top_risks([capability, actionable], limit=1) == [actionable]
