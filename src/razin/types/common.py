"""Cross-module type aliases."""

from __future__ import annotations

from typing import Literal

type Severity = Literal["low", "medium", "high"]
type Confidence = Literal["low", "medium", "high"]
type Classification = Literal["security", "informational"]
type RuleDisableSource = Literal["config", "cli-disable", "cli-only"]
type SignalKind = Literal[
    "capability",
    "review",
    "dangerous_behavior",
    "known_malicious_ioc",
    "integrity_violation",
    "attack_chain",
    "analysis_gap",
]
type EvidenceVerdict = Literal[
    "high-confidence-malicious-evidence",
    "review-required",
    "capability-only",
    "no-actionable-malicious-evidence",
]
type WorkspaceEvidenceVerdict = Literal[
    "contains-high-confidence-malicious-evidence",
    "review-required",
    "capability-only",
    "no-actionable-malicious-evidence",
]
type CoverageStatus = Literal["complete", "incomplete", "not-evaluated"]

# Deprecated Python compatibility aliases. Version 3 reports no longer
# serialize these lossy composite states.
type AssessmentState = Literal[
    "malicious/high-confidence-chain",
    "risky-but-legitimate/review",
    "dynamic-analysis-required/unknown",
    "clean/no-evidence",
]
type WorkspaceAssessment = Literal[
    "contains-high-confidence-malicious",
    "review-required",
    "incomplete",
    "clean",
]

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]
