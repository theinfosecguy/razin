"""Tests for label-agnostic detector feature extraction."""

from __future__ import annotations

import json

import pytest

import razin.scanner.features as feature_module
from razin.model import Evidence, Finding
from razin.scanner.features import (
    detector_feature_contract,
    extract_detector_features,
    feature_contract_sha256,
)


def _finding(rule_id: str, score: int, *, finding_id: str = "secret-finding-id") -> Finding:
    return Finding(
        id=finding_id,
        severity="high" if score >= 70 else "medium",
        score=score,
        confidence="high",
        title="private title",
        description="private evidence description",
        evidence=Evidence(path="/private/corpus/sample/SKILL.md", line=7, snippet="private snippet"),
        skill="private-skill-name",
        rule_id=rule_id,
        recommendation="private recommendation",
    )


def test_feature_order_and_serialization_are_deterministic() -> None:
    findings = [_finding("NET_RAW_IP", 60), _finding("BUNDLED_SCRIPTS", 39)]

    forward = extract_detector_features(findings)
    reverse = extract_detector_features(reversed(findings))

    assert forward.to_dict() == reverse.to_dict()
    assert [feature.rule_id for feature in forward.rules] == ["BUNDLED_SCRIPTS", "NET_RAW_IP"]


def test_duplicate_findings_preserve_count_and_binary_presence() -> None:
    vector = extract_detector_features([_finding("NET_RAW_IP", 55), _finding("NET_RAW_IP", 69)])

    assert vector.present_rule_ids == ("NET_RAW_IP",)
    assert vector.rules[0].count == 2
    assert vector.rules[0].max_score == 69


def test_extractor_never_serializes_evidence_or_identity_fields() -> None:
    rendered = json.dumps(extract_detector_features([_finding("NET_RAW_IP", 60)]).to_dict(), sort_keys=True)

    for forbidden in (
        "secret-finding-id",
        "private title",
        "private evidence description",
        "/private/corpus",
        "private snippet",
        "private-skill-name",
    ):
        assert forbidden not in rendered


def test_model_eligibility_excludes_gaps_inventory_unknown_and_typosquat() -> None:
    vector = extract_detector_features(
        [
            _finding("INCOMPLETE_SCAN", 0),
            _finding("PACKAGE_INVENTORY", 0),
            _finding("TYPOSQUAT", 60),
            _finding("UNREVIEWED_CUSTOM_RULE", 60),
            _finding("BUNDLED_SCRIPTS", 39),
        ]
    )
    by_rule = {feature.rule_id: feature for feature in vector.rules}

    assert by_rule["BUNDLED_SCRIPTS"].model_eligible is True
    for rule_id in ("INCOMPLETE_SCAN", "PACKAGE_INVENTORY", "TYPOSQUAT", "UNREVIEWED_CUSTOM_RULE"):
        assert by_rule[rule_id].model_eligible is False
        assert by_rule[rule_id].exclusion_reason


def test_model_eligibility_excludes_operator_configured_matching_rules() -> None:
    rule_ids = (
        "DATA_SENSITIVITY",
        "KNOWN_BAD_DOMAIN",
        "KNOWN_BAD_FILE_HASH",
        "KNOWN_BAD_INDICATOR",
        "MCP_DENYLIST",
        "MCP_ENDPOINT",
        "MCP_REMOTE_DENYLIST",
        "NET_DOC_DOMAIN",
        "NET_UNKNOWN_DOMAIN",
        "PACKAGE_DATA_EXFILTRATION",
        "TOOL_INVOCATION",
    )

    vector = extract_detector_features(_finding(rule_id, 60) for rule_id in rule_ids)

    assert vector.present_rule_ids == ()
    assert all(feature.exclusion_reason for feature in vector.rules)


def test_feature_contract_hash_is_stable_and_documents_forbidden_inputs() -> None:
    contract = detector_feature_contract()
    forbidden_inputs = contract["forbidden_inputs"]
    unknown = extract_detector_features([_finding("UNREVIEWED_CUSTOM_RULE", 60)]).rules[0]

    assert contract["representation"] == "binary-rule-presence-v1"
    assert contract["model_input_fields"] == ["features.present_rule_ids"]
    assert contract["unknown_rule_policy"] == {
        "signal_kind": unknown.signal_kind,
        "model_eligible": unknown.model_eligible,
        "exclusion_reason": unknown.exclusion_reason,
    }
    assert isinstance(forbidden_inputs, list)
    assert "label" in forbidden_inputs
    assert len(feature_contract_sha256()) == 64


def test_feature_contract_hash_changes_with_rule_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    original = feature_contract_sha256()
    monkeypatch.setitem(feature_module.RULE_SIGNAL_KINDS, "NEW_REVIEWED_RULE", "review")

    assert feature_contract_sha256() != original
