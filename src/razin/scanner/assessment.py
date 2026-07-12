"""Truthful package assessment and review-priority semantics.

The numeric value produced here is a triage aid, not a probability of
maliciousness. Rule signal kinds are intentionally explicit: a new rule is an
analysis gap until its evidence contract is reviewed and registered below.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from razin.model import Finding
from razin.types import AssessmentState, Severity, SignalKind, WorkspaceAssessment

ASSESSMENT_STATES: tuple[AssessmentState, ...] = (
    "malicious/high-confidence-chain",
    "risky-but-legitimate/review",
    "dynamic-analysis-required/unknown",
    "clean/no-evidence",
)

STRONG_SIGNAL_KINDS: frozenset[SignalKind] = frozenset({"known_malicious_ioc", "integrity_violation", "attack_chain"})
HIGH_PRIORITY_SIGNAL_KINDS: frozenset[SignalKind] = STRONG_SIGNAL_KINDS | {"dangerous_behavior"}

# Presence and capability signals describe attack surface, not maliciousness.
# Review signals are suspicious but ambiguous. Dangerous behavior may remain
# high priority while only the three strong kinds make a malicious assessment.
RULE_SIGNAL_KINDS: dict[str, SignalKind] = {
    "AUTH_CONNECTION": "capability",
    "BUNDLED_SCRIPTS": "capability",
    "CONFUSABLE_IDENTIFIER_EXTENDED": "review",
    "DATA_SENSITIVITY": "capability",
    "DYNAMIC_SCHEMA": "capability",
    "EXEC_FIELDS": "capability",
    "HIDDEN_INSTRUCTION": "review",
    "INSTR_OBFUSCATED_PAYLOAD": "integrity_violation",
    "INCOMPLETE_SCAN": "analysis_gap",
    "DYNAMIC_ANALYSIS_REQUIRED": "analysis_gap",
    "KNOWN_BAD_DOMAIN": "review",
    "KNOWN_BAD_FILE_HASH": "known_malicious_ioc",
    "KNOWN_BAD_INDICATOR": "review",
    "MCP_DENYLIST": "review",
    "MCP_ENDPOINT": "capability",
    "MCP_REMOTE_DENYLIST": "review",
    "MCP_REMOTE_NON_HTTPS": "review",
    "MCP_REMOTE_RAW_IP": "review",
    "MCP_REQUIRED": "capability",
    "NET_DOC_DOMAIN": "capability",
    "NET_RAW_IP": "review",
    "NET_UNKNOWN_DOMAIN": "capability",
    "OPAQUE_BLOB": "review",
    "PROMPT_INJECTION": "review",
    "PACKAGE_DATA_EXFILTRATION": "attack_chain",
    "PACKAGE_INVENTORY": "capability",
    "PACKAGE_REMOTE_CODE_EXECUTION": "dangerous_behavior",
    "PACKAGE_SENSITIVE_NETWORK_FLOW": "review",
    "REMOTE_REFERENCE_RISK": "review",
    "SECRET_REF": "capability",
    "TOOL_INVOCATION": "capability",
    "TYPOSQUAT": "review",
    "UNICODE_BIDI_CONTROL": "review",
    "MUTABLE_REMOTE_REFERENCE": "review",
}

RESERVED_STRONG_RULE_IDS: frozenset[str] = frozenset(
    rule_id for rule_id, signal_kind in RULE_SIGNAL_KINDS.items() if signal_kind in STRONG_SIGNAL_KINDS
)


def signal_kind_for_rule(
    rule_id: str,
    *,
    registry: Mapping[str, SignalKind] | None = None,
) -> SignalKind:
    """Return a rule's evidence kind, defaulting unknown rules to analysis gap."""
    source = RULE_SIGNAL_KINDS if registry is None else registry
    return source.get(rule_id, "analysis_gap")


def max_allowed_severity(signal_kind: SignalKind) -> Severity:
    """Return the highest severity permitted by a signal's evidence contract."""
    if signal_kind == "capability":
        return "low"
    if signal_kind in HIGH_PRIORITY_SIGNAL_KINDS:
        return "high"
    return "medium"


def assess_package(findings: Iterable[Finding]) -> AssessmentState:
    """Classify a package from evidence without claiming capabilities are attacks."""
    observed = tuple(findings)
    if not observed:
        return "clean/no-evidence"

    if any(signal_kind_for_rule(finding.rule_id) in STRONG_SIGNAL_KINDS for finding in observed):
        return "malicious/high-confidence-chain"
    if any(signal_kind_for_rule(finding.rule_id) == "analysis_gap" for finding in observed):
        return "dynamic-analysis-required/unknown"
    if any(signal_kind_for_rule(finding.rule_id) in {"review", "dangerous_behavior"} for finding in observed):
        return "risky-but-legitimate/review"
    return "clean/no-evidence"


def package_assessment_counts(
    findings_by_package: Mapping[str, Iterable[Finding]],
    *,
    total_packages: int | None = None,
) -> dict[AssessmentState, int]:
    """Count per-package assessment states without flattening package boundaries."""
    counts: dict[AssessmentState, int] = {state: 0 for state in ASSESSMENT_STATES}
    for findings in findings_by_package.values():
        counts[assess_package(findings)] += 1

    if total_packages is not None:
        unrepresented = max(0, total_packages - len(findings_by_package))
        counts["clean/no-evidence"] += unrepresented
    return counts


def package_assessment_counts_from_findings(
    findings: Iterable[Finding],
    *,
    total_packages: int,
) -> dict[AssessmentState, int]:
    """Reconstruct package-state counts for reporting compatibility paths."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.skill, []).append(finding)
    return package_assessment_counts(grouped, total_packages=total_packages)


def assess_workspace(counts: Mapping[AssessmentState, int]) -> WorkspaceAssessment:
    """Return a workspace verdict while preserving package-state counts separately."""
    if counts.get("malicious/high-confidence-chain", 0) > 0:
        return "contains-high-confidence-malicious"
    if counts.get("dynamic-analysis-required/unknown", 0) > 0:
        return "incomplete"
    if counts.get("risky-but-legitimate/review", 0) > 0:
        return "review-required"
    return "clean"


def review_priority_score(findings: Iterable[Finding]) -> int:
    """Return a non-probabilistic 0-100 triage priority.

    The highest actionable evidence wins. Correlated findings are not combined,
    informational capability inventory is excluded, and non-strong signals are
    capped below the high-priority band.
    """
    actionable = [
        finding
        for finding in findings
        if finding.classification == "security" and signal_kind_for_rule(finding.rule_id) != "capability"
    ]
    if not actionable:
        return 0

    priorities: list[int] = []
    for finding in actionable:
        score = max(0, min(100, finding.score))
        if signal_kind_for_rule(finding.rule_id) not in HIGH_PRIORITY_SIGNAL_KINDS:
            score = min(score, 69)
        priorities.append(score)
    return max(priorities, default=0)
