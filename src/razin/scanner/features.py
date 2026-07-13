"""Deterministic, label-agnostic detector feature extraction."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass

from razin.model import Finding
from razin.scanner.assessment import RULE_SIGNAL_KINDS, signal_kind_for_rule
from razin.types import SignalKind

FEATURE_SCHEMA_VERSION = "1.0"
FEATURE_REPRESENTATION = "binary-rule-presence-v1"

EXCLUDED_RULE_IDS: dict[str, str] = {
    "DATA_SENSITIVITY": "operator-configured services and keywords can encode corpus labels",
    "KNOWN_BAD_DOMAIN": "operator-configured indicator can encode corpus labels",
    "KNOWN_BAD_FILE_HASH": "operator-configured indicator can encode corpus labels",
    "KNOWN_BAD_INDICATOR": "operator-configured indicator can encode corpus labels",
    "MCP_DENYLIST": "operator-configured denylist can encode corpus labels",
    "MCP_ENDPOINT": "operator-configured allowlist can encode corpus labels",
    "MCP_REMOTE_DENYLIST": "operator-configured denylist can encode corpus labels",
    "NET_DOC_DOMAIN": "operator-configured allowlist and denylist can encode corpus labels",
    "NET_UNKNOWN_DOMAIN": "operator-configured allowlist and denylist can encode corpus labels",
    "PACKAGE_DATA_EXFILTRATION": "operator-configured known-bad domains can encode corpus labels",
    "PACKAGE_INVENTORY": "inventory metadata is not detector evidence",
    "TOOL_INVOCATION": "operator-configured prefixes and tier keywords can encode corpus labels",
    "TYPOSQUAT": "workspace-derived baseline can observe held-out package names",
}


@dataclass(frozen=True)
class RuleFeature:
    """Auditable aggregate for one detector rule."""

    rule_id: str
    count: int
    max_score: int
    signal_kind: SignalKind
    model_eligible: bool
    exclusion_reason: str | None


@dataclass(frozen=True)
class DetectorFeatureVector:
    """Stable feature vector containing no evidence text, paths, or labels."""

    schema_version: str
    rules: tuple[RuleFeature, ...]

    @property
    def present_rule_ids(self) -> tuple[str, ...]:
        """Return model-eligible binary rule-presence features."""
        return tuple(feature.rule_id for feature in self.rules if feature.model_eligible)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "schema_version": self.schema_version,
            "present_rule_ids": list(self.present_rule_ids),
            "rules": [asdict(feature) for feature in self.rules],
        }


def detector_feature_contract() -> dict[str, object]:
    """Return the immutable feature-selection contract."""
    eligibility = {
        rule_id: _eligibility_contract(rule_id, signal_kind)
        for rule_id, signal_kind in sorted(RULE_SIGNAL_KINDS.items())
    }
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "representation": FEATURE_REPRESENTATION,
        "model_input": "eligible binary rule presence only",
        "model_input_fields": ["features.present_rule_ids"],
        "evaluation_metadata_fields": [
            "target.label",
            "metadata.id",
            "metadata.coverage_status",
            "metadata.package_analysis_digest",
            "metadata.package_analysis_digest_version",
            "metadata.diagnostic_family",
            "metadata.diagnostic_group",
            "metadata.diagnostic_family_authoritative",
            "metadata.diagnostic_group_authoritative",
            "metadata.campaign_lineage_authoritative",
            "audit.rules",
        ],
        "excluded_signal_kinds": {"analysis_gap": "coverage state or unreviewed evidence contract"},
        "excluded_rule_ids": dict(sorted(EXCLUDED_RULE_IDS.items())),
        "rule_eligibility": eligibility,
        "unknown_rule_policy": {
            "signal_kind": "analysis_gap",
            "model_eligible": False,
            "exclusion_reason": "analysis-gap signals are not classifier inputs",
        },
        "forbidden_inputs": [
            "assessment or evidence verdict",
            "coverage status",
            "evidence text or path",
            "finding id",
            "label",
            "sample id",
            "family, campaign, or lineage",
            "package digest",
        ],
    }


def feature_contract_sha256() -> str:
    """Hash the canonical feature contract for provenance."""
    contract = detector_feature_contract()
    machine_contract = {
        key: contract[key]
        for key in (
            "schema_version",
            "representation",
            "model_input_fields",
            "rule_eligibility",
            "unknown_rule_policy",
        )
    }
    payload = json.dumps(machine_contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _eligibility_contract(rule_id: str, signal_kind: SignalKind) -> dict[str, object]:
    exclusion_reason = EXCLUDED_RULE_IDS.get(rule_id)
    if exclusion_reason is None and signal_kind == "analysis_gap":
        exclusion_reason = "analysis-gap signals are not classifier inputs"
    return {
        "signal_kind": signal_kind,
        "model_eligible": exclusion_reason is None,
        "exclusion_reason": exclusion_reason,
    }


def extract_detector_features(findings: Iterable[Finding]) -> DetectorFeatureVector:
    """Aggregate findings without accepting labels or sample metadata."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.rule_id, []).append(finding)

    features: list[RuleFeature] = []
    for rule_id, observed in sorted(grouped.items()):
        signal_kind = signal_kind_for_rule(rule_id)
        eligibility = _eligibility_contract(rule_id, signal_kind)
        exclusion_reason = eligibility["exclusion_reason"]
        assert exclusion_reason is None or isinstance(exclusion_reason, str)
        features.append(
            RuleFeature(
                rule_id=rule_id,
                count=len(observed),
                max_score=max(finding.score for finding in observed),
                signal_kind=signal_kind,
                model_eligible=bool(eligibility["model_eligible"]),
                exclusion_reason=exclusion_reason,
            )
        )

    return DetectorFeatureVector(schema_version=FEATURE_SCHEMA_VERSION, rules=tuple(features))
