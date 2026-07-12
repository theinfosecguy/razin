"""Tests for evidence contracts, package states, and review priority."""

from __future__ import annotations

from razin.model import Evidence, Finding, FindingCandidate
from razin.scanner.assessment import (
    assess_package,
    assess_workspace,
    coverage_status_for_package,
    evidence_verdict_for_package,
    package_assessment_counts,
    package_coverage_counts,
    package_evidence_verdict_counts,
    review_priority_score,
    signal_kind_for_rule,
    workspace_coverage_status,
    workspace_evidence_verdict,
)
from razin.scanner.pipeline.conversion import candidate_to_finding, deserialize_findings
from razin.types import Classification, Severity, SignalKind
from razin.types.config import RuleOverrideConfig


def _finding(
    *,
    rule_id: str,
    score: int,
    signal_kind: SignalKind,
    classification: Classification = "security",
) -> Finding:
    severity: Severity = "high" if score >= 70 else ("medium" if score >= 40 else "low")
    return Finding(
        id=rule_id,
        severity=severity,
        score=score,
        confidence="high",
        title=rule_id,
        description="test",
        evidence=Evidence(path="SKILL.md", line=1, snippet="test"),
        skill="skill",
        rule_id=rule_id,
        recommendation="review",
        classification=classification,
        signal_kind=signal_kind,
    )


def _candidate(rule_id: str, score: int = 90) -> FindingCandidate:
    return FindingCandidate(
        rule_id=rule_id,
        score=score,
        confidence="high",
        title=rule_id,
        description="test",
        evidence=Evidence(path="SKILL.md", line=1, snippet="test"),
        recommendation="review",
    )


def test_unknown_rule_defaults_to_analysis_gap_and_cannot_be_high() -> None:
    finding = candidate_to_finding("skill", _candidate("NEW_UNREVIEWED_RULE"))

    assert signal_kind_for_rule("NEW_UNREVIEWED_RULE") == "analysis_gap"
    assert finding.signal_kind == "analysis_gap"
    assert finding.severity == "medium"
    assert finding.score == 69
    assert evidence_verdict_for_package([finding]) == "review-required"


def test_capability_is_informational_low_and_has_no_priority() -> None:
    finding = candidate_to_finding("skill", _candidate("BUNDLED_SCRIPTS"))

    assert finding.signal_kind == "capability"
    assert finding.classification == "informational"
    assert finding.severity == "low"
    assert finding.score == 39
    assert review_priority_score([finding]) == 0
    assert evidence_verdict_for_package([finding]) == "capability-only"


def test_capability_cannot_gain_priority_from_inconsistent_security_classification() -> None:
    forged = _finding(
        rule_id="SECRET_REF",
        score=100,
        signal_kind="capability",
        classification="security",
    )

    assert review_priority_score([forged]) == 0


def test_review_signal_cannot_make_high_confidence_malicious_claim() -> None:
    finding = candidate_to_finding("skill", _candidate("PROMPT_INJECTION"))

    assert finding.signal_kind == "review"
    assert finding.severity == "medium"
    assert evidence_verdict_for_package([finding]) == "review-required"


def test_composed_attack_chain_can_be_high_confidence_malicious() -> None:
    finding = candidate_to_finding("skill", _candidate("PACKAGE_DATA_EXFILTRATION"))

    assert finding.signal_kind == "attack_chain"
    assert finding.severity == "high"
    assert review_priority_score([finding]) == 90
    assert evidence_verdict_for_package([finding]) == "high-confidence-malicious-evidence"


def test_dangerous_remote_execution_is_high_priority_without_claiming_malicious_intent() -> None:
    finding = candidate_to_finding("skill", _candidate("PACKAGE_REMOTE_CODE_EXECUTION", 96))

    assert finding.signal_kind == "dangerous_behavior"
    assert finding.severity == "high"
    assert review_priority_score([finding]) == 96
    assert evidence_verdict_for_package([finding]) == "review-required"


def test_strong_assessment_is_independent_of_display_thresholds_and_caps() -> None:
    balanced = candidate_to_finding(
        "skill",
        _candidate("PACKAGE_DATA_EXFILTRATION"),
        high_severity_min=95,
        medium_severity_min=50,
    )
    policy_capped = candidate_to_finding(
        "skill",
        _candidate("KNOWN_BAD_FILE_HASH"),
        rule_override=RuleOverrideConfig(max_severity="low"),
    )

    assert balanced.severity == "medium"
    assert policy_capped.severity == "low"
    assert evidence_verdict_for_package([balanced]) == "high-confidence-malicious-evidence"
    assert evidence_verdict_for_package([policy_capped]) == "high-confidence-malicious-evidence"


def test_policy_denylist_is_review_evidence_not_known_malicious_ioc() -> None:
    for rule_id in ("MCP_DENYLIST", "MCP_REMOTE_DENYLIST"):
        finding = candidate_to_finding("skill", _candidate(rule_id))
        assert finding.signal_kind == "review"
        assert finding.severity == "medium"
        assert evidence_verdict_for_package([finding]) == "review-required"


def test_deserialization_derives_signal_kind_instead_of_trusting_cache() -> None:
    capability = _finding(rule_id="SECRET_REF", score=100, signal_kind="capability").to_dict()
    capability["signal_kind"] = "attack_chain"
    unknown = _finding(rule_id="UNREVIEWED_PLUGIN_RULE", score=100, signal_kind="analysis_gap").to_dict()
    unknown["signal_kind"] = "known_malicious_ioc"
    attack_chain = _finding(
        rule_id="PACKAGE_DATA_EXFILTRATION",
        score=90,
        signal_kind="attack_chain",
    ).to_dict()
    attack_chain["signal_kind"] = "capability"

    findings = deserialize_findings([capability, unknown, attack_chain])

    assert [finding.signal_kind for finding in findings] == ["capability", "analysis_gap", "attack_chain"]
    assert review_priority_score(findings[:1]) == 0
    assert evidence_verdict_for_package(findings[1:2]) == "review-required"


def test_priority_uses_strongest_evidence_without_probability_combination() -> None:
    findings = [
        _finding(rule_id="A", score=58, signal_kind="review"),
        _finding(rule_id="B", score=62, signal_kind="review"),
        _finding(
            rule_id="CAPABILITY",
            score=39,
            signal_kind="capability",
            classification="informational",
        ),
    ]

    assert review_priority_score(findings) == 62


def test_empty_package_has_no_actionable_evidence_state() -> None:
    assert review_priority_score([]) == 0
    assert evidence_verdict_for_package([]) == "no-actionable-malicious-evidence"


def test_workspace_preserves_independent_evidence_and_coverage_axes() -> None:
    packages = {
        "malicious": [_finding(rule_id="PACKAGE_DATA_EXFILTRATION", score=90, signal_kind="attack_chain")],
        "review": [_finding(rule_id="PROMPT_INJECTION", score=60, signal_kind="review")],
        "incomplete": [
            _finding(
                rule_id="INCOMPLETE_SCAN",
                score=40,
                signal_kind="analysis_gap",
                classification="informational",
            )
        ],
        "clean": [],
    }

    verdict_counts = package_evidence_verdict_counts(packages)
    coverage_counts = package_coverage_counts(
        {"malicious": "complete", "review": "complete", "incomplete": "incomplete", "clean": "complete"}
    )

    assert verdict_counts == {
        "high-confidence-malicious-evidence": 1,
        "review-required": 1,
        "capability-only": 0,
        "no-actionable-malicious-evidence": 2,
    }
    assert coverage_counts == {"complete": 3, "incomplete": 1, "not-evaluated": 0}
    assert workspace_evidence_verdict(verdict_counts) == "contains-high-confidence-malicious-evidence"
    assert workspace_coverage_status(coverage_counts) == "incomplete"


def test_coverage_fallback_never_claims_complete_without_structured_state() -> None:
    gap = _finding(rule_id="INCOMPLETE_SCAN", score=40, signal_kind="analysis_gap")

    assert coverage_status_for_package([gap]) == "incomplete"
    assert coverage_status_for_package([]) == "not-evaluated"


def test_empty_workspace_coverage_is_not_evaluated() -> None:
    assert workspace_coverage_status({"complete": 0, "incomplete": 0, "not-evaluated": 0}) == "not-evaluated"


def test_v2_python_assessment_aliases_remain_available() -> None:
    findings = [_finding(rule_id="PROMPT_INJECTION", score=60, signal_kind="review")]
    counts = package_assessment_counts({"skill": findings})

    assert assess_package(findings) == "risky-but-legitimate/review"
    assert assess_workspace(counts) == "review-required"
