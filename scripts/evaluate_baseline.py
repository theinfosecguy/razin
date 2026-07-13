#!/usr/bin/env python3
"""Evaluate a leakage-resistant, group-disjoint Bernoulli NB baseline.

This research harness is deliberately separate from Razin scan verdicts. It
never trains without an authoritative relationship sidecar and never treats an
incomplete static scan as a successful prediction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any, Literal

from razin.scanner.features import detector_feature_contract, feature_contract_sha256

SCHEMA_VERSION = "1.0"
METHOD = "bernoulli-nb"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
METRIC_RANGE_FIELDS = (
    "precision",
    "recall",
    "specificity",
    "false_positive_rate",
    "balanced_accuracy",
    "matthews_correlation_coefficient",
)

Label = Literal["benign", "malicious"]
CoverageStatus = Literal["complete", "incomplete", "not-evaluated"]


class BaselineError(ValueError):
    """Raised for malformed or unsafe baseline inputs."""


@dataclass(frozen=True)
class Sample:
    """Strictly separated model input and evaluation metadata."""

    sample_id: str
    label: Label
    coverage_status: CoverageStatus
    present_rule_ids: frozenset[str]


@dataclass(frozen=True)
class Relationship:
    """One authoritative relationship from the trusted sidecar."""

    kind: str
    relationship_id: str
    sample_ids: tuple[str, ...]

    @property
    def qualified_id(self) -> str:
        """Disambiguate campaign, lineage, and control namespaces."""
        return f"{self.kind}:{self.relationship_id}"


@dataclass(frozen=True)
class Component:
    """Connected holdout unit that may never cross train and test."""

    component_id: str
    sample_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    malicious_complete: int
    benign_complete: int


@dataclass(frozen=True)
class BaselineConfig:
    """Frozen, intentionally narrow reference-model configuration."""

    alpha: float
    folds: int
    decision_threshold: float

    def to_dict(self) -> dict[str, object]:
        """Return the canonical public configuration."""
        return {
            "schema_version": SCHEMA_VERSION,
            "method": METHOD,
            "alpha": self.alpha,
            "folds": self.folds,
            "class_prior": "empirical",
            "decision_threshold": self.decision_threshold,
            "tie_break": "benign",
            "feature_space": "training-fold-only",
            "component_policy": "campaign-lineage-connected-components",
            "fold_assignment": "deterministic-label-balanced-components",
            "coverage_policy": "abstain-and-count-as-opposite-class-error",
        }


@dataclass(frozen=True)
class BernoulliModel:
    """Interpretable Bernoulli Naive Bayes parameters for one fold."""

    vocabulary: tuple[str, ...]
    prior_log_odds: float
    probabilities: dict[str, tuple[float, float]]

    def score(self, present: frozenset[str]) -> tuple[float, list[dict[str, object]]]:
        """Return malicious log odds and every feature contribution."""
        log_odds = self.prior_log_odds
        contributions: list[dict[str, object]] = []
        for rule_id in self.vocabulary:
            malicious_probability, benign_probability = self.probabilities[rule_id]
            is_present = rule_id in present
            if is_present:
                contribution = math.log(malicious_probability / benign_probability)
            else:
                contribution = math.log((1.0 - malicious_probability) / (1.0 - benign_probability))
            log_odds += contribution
            contributions.append(
                {
                    "rule_id": rule_id,
                    "present": is_present,
                    "malicious_log_odds_contribution": contribution,
                }
            )
        return log_odds, contributions

    def audit_parameters(self) -> list[dict[str, object]]:
        """Return probabilities and present/absent log-odds contributions."""
        rows: list[dict[str, object]] = []
        for rule_id in self.vocabulary:
            malicious_probability, benign_probability = self.probabilities[rule_id]
            rows.append(
                {
                    "rule_id": rule_id,
                    "malicious_presence_probability": malicious_probability,
                    "benign_presence_probability": benign_probability,
                    "present_log_odds_contribution": math.log(malicious_probability / benign_probability),
                    "absent_log_odds_contribution": math.log(
                        (1.0 - malicious_probability) / (1.0 - benign_probability)
                    ),
                }
            )
        return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schema_sha256(filename: str) -> str:
    schema = Path(__file__).resolve().parents[1] / "schemas" / "v1" / filename
    return _sha256(schema)


def _read_json(path: Path, *, name: str) -> tuple[dict[str, Any], str]:
    payload = path.read_bytes()
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise BaselineError(f"{name} must be a JSON object")
    return raw, hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _exact_keys(raw: dict[str, Any], expected: set[str], *, name: str) -> None:
    actual = set(raw)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise BaselineError(f"{name} fields mismatch: missing={missing}, unknown={unknown}")


def _load_config_with_sha256(path: Path) -> tuple[BaselineConfig, str]:
    raw, digest = _read_json(path, name="baseline config")
    _exact_keys(
        raw,
        {
            "schema_version",
            "method",
            "alpha",
            "folds",
            "class_prior",
            "decision_threshold",
            "tie_break",
        },
        name="baseline config",
    )
    if raw["schema_version"] != SCHEMA_VERSION or raw["method"] != METHOD:
        raise BaselineError("baseline config schema_version or method is unsupported")
    if not isinstance(raw["alpha"], (int, float)) or isinstance(raw["alpha"], bool) or raw["alpha"] != 1.0:
        raise BaselineError("baseline config alpha must be exactly 1.0")
    if raw["class_prior"] != "empirical":
        raise BaselineError("baseline config class_prior must be empirical")
    if (
        not isinstance(raw["decision_threshold"], (int, float))
        or isinstance(raw["decision_threshold"], bool)
        or raw["decision_threshold"] != 0.0
    ):
        raise BaselineError("baseline config decision_threshold must be exactly 0.0")
    if raw["tie_break"] != "benign":
        raise BaselineError("baseline config tie_break must be benign")
    folds = raw["folds"]
    if not isinstance(folds, int) or isinstance(folds, bool) or folds != 3:
        raise BaselineError("baseline config folds must be exactly 3")
    return BaselineConfig(alpha=1.0, folds=folds, decision_threshold=0.0), digest


def load_config(path: Path) -> BaselineConfig:
    """Load the fixed reference-model contract without tuning knobs."""
    config, _ = _load_config_with_sha256(path)
    return config


def _validate_feature_audit(
    sample: dict[str, Any],
    *,
    index: int,
    contract: dict[str, Any],
) -> tuple[str, Label, CoverageStatus, frozenset[str]]:
    prefix = f"feature artifact samples[{index}]"
    _exact_keys(sample, {"features", "target", "metadata", "audit"}, name=prefix)
    features = sample["features"]
    target = sample["target"]
    metadata = sample["metadata"]
    audit = sample["audit"]
    if not all(isinstance(value, dict) for value in (features, target, metadata, audit)):
        raise BaselineError(f"{prefix} sections must be objects")

    _exact_keys(features, {"present_rule_ids"}, name=f"{prefix}.features")
    present = features["present_rule_ids"]
    if not isinstance(present, list) or not all(isinstance(item, str) for item in present):
        raise BaselineError(f"{prefix}.features.present_rule_ids must be an array of strings")
    if present != sorted(set(present)):
        raise BaselineError(f"{prefix}.features.present_rule_ids must be sorted and unique")

    label = target.get("label")
    if label not in {"benign", "malicious"}:
        raise BaselineError(f"{prefix}.target.label is invalid")
    sample_id = metadata.get("id")
    coverage = metadata.get("coverage_status")
    if not isinstance(sample_id, str) or not sample_id:
        raise BaselineError(f"{prefix}.metadata.id must be a non-empty string")
    if coverage not in {"complete", "incomplete", "not-evaluated"}:
        raise BaselineError(f"{prefix}.metadata.coverage_status is invalid")

    rules = audit.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise BaselineError(f"{prefix}.audit.rules must be an array of objects")
    registry = contract.get("rule_eligibility")
    unknown = contract.get("unknown_rule_policy")
    if not isinstance(registry, dict) or not isinstance(unknown, dict):
        raise BaselineError("feature artifact eligibility contract is malformed")
    observed_ids: list[str] = []
    eligible_ids: list[str] = []
    for rule_index, rule in enumerate(rules):
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str):
            raise BaselineError(f"{prefix}.audit.rules[{rule_index}].rule_id must be a string")
        expected = registry.get(rule_id, unknown)
        if not isinstance(expected, dict):
            raise BaselineError("feature artifact eligibility contract is malformed")
        for field in ("signal_kind", "model_eligible", "exclusion_reason"):
            observed = rule.get(field)
            required = expected.get(field)
            if field == "model_eligible":
                matches = type(observed) is bool and observed is required
            else:
                matches = type(observed) is type(required) and observed == required
            if not matches:
                raise BaselineError(f"{prefix}.audit.rules[{rule_index}] contradicts the feature contract")
        observed_ids.append(rule_id)
        if rule.get("model_eligible") is True:
            eligible_ids.append(rule_id)
    if observed_ids != sorted(set(observed_ids)):
        raise BaselineError(f"{prefix}.audit.rules must have sorted, unique rule IDs")
    if eligible_ids != present:
        raise BaselineError(f"{prefix}.features must exactly match eligible audit rules")
    return sample_id, label, coverage, frozenset(present)


def load_feature_artifact(path: Path) -> tuple[list[Sample], dict[str, Any], str]:
    """Load feature rows while preserving the structural leakage boundary."""
    raw, digest = _read_json(path, name="feature artifact")
    if raw.get("schema_version") != SCHEMA_VERSION or raw.get("status") != "research-only":
        raise BaselineError("feature artifact must be research-only schema 1.0")
    contract = raw.get("contract")
    provenance = raw.get("provenance")
    raw_samples = raw.get("samples")
    if not isinstance(contract, dict) or not isinstance(provenance, dict) or not isinstance(raw_samples, list):
        raise BaselineError("feature artifact is missing contract, provenance, or samples")
    if contract.get("model_input_fields") != ["features.present_rule_ids"]:
        raise BaselineError("feature artifact declares an unsupported model input")
    if _canonical_json(contract) != _canonical_json(detector_feature_contract()):
        raise BaselineError("feature artifact embeds a modified or unsupported feature contract")
    expected_hash = feature_contract_sha256()
    if provenance.get("feature_contract_sha256") != expected_hash:
        raise BaselineError("feature artifact contract hash does not match this evaluator")

    samples: list[Sample] = []
    ids: set[str] = set()
    for index, raw_sample in enumerate(raw_samples):
        if not isinstance(raw_sample, dict):
            raise BaselineError(f"feature artifact samples[{index}] must be an object")
        sample_id, label, coverage, present = _validate_feature_audit(raw_sample, index=index, contract=contract)
        if sample_id in ids:
            raise BaselineError(f"feature artifact contains duplicate sample id {sample_id!r}")
        ids.add(sample_id)
        samples.append(Sample(sample_id, label, coverage, present))
    if not samples:
        raise BaselineError("feature artifact contains no samples")
    return samples, provenance, digest


def load_relationships(
    path: Path,
    *,
    sample_ids: set[str],
    expected_manifest_sha256: str,
) -> tuple[list[Relationship], dict[str, str], str]:
    """Load an authoritative, label-free relationship sidecar."""
    raw, digest = _read_json(path, name="grouping sidecar")
    _exact_keys(raw, {"schema_version", "authority", "relationships"}, name="grouping sidecar")
    if raw["schema_version"] != SCHEMA_VERSION:
        raise BaselineError("grouping sidecar schema_version is unsupported")
    authority = raw["authority"]
    if not isinstance(authority, dict):
        raise BaselineError("grouping sidecar authority must be an object")
    _exact_keys(authority, {"status", "source", "manifest_sha256"}, name="grouping sidecar authority")
    if authority["status"] != "authoritative":
        raise BaselineError("grouping sidecar must explicitly be authoritative")
    if not isinstance(authority["source"], str) or not authority["source"]:
        raise BaselineError("grouping authority source must be a non-empty string")
    manifest_sha256 = authority["manifest_sha256"]
    if not isinstance(manifest_sha256, str) or not SHA256_RE.fullmatch(manifest_sha256):
        raise BaselineError("grouping authority manifest_sha256 must be a lowercase SHA-256")
    if manifest_sha256 != expected_manifest_sha256:
        raise BaselineError("grouping sidecar is not bound to the feature artifact manifest")

    raw_relationships = raw["relationships"]
    if not isinstance(raw_relationships, list) or not raw_relationships:
        raise BaselineError("grouping sidecar relationships must be a non-empty array")
    relationships: list[Relationship] = []
    qualified_ids: set[str] = set()
    covered: set[str] = set()
    for index, item in enumerate(raw_relationships):
        if not isinstance(item, dict):
            raise BaselineError(f"grouping relationship[{index}] must be an object")
        _exact_keys(item, {"kind", "id", "sample_ids"}, name=f"grouping relationship[{index}]")
        kind = item["kind"]
        relationship_id = item["id"]
        members = item["sample_ids"]
        if kind not in {"campaign", "lineage", "independent"}:
            raise BaselineError(f"grouping relationship[{index}].kind is invalid")
        if not isinstance(relationship_id, str) or not relationship_id:
            raise BaselineError(f"grouping relationship[{index}].id must be a non-empty string")
        if not isinstance(members, list) or not members or not all(isinstance(member, str) for member in members):
            raise BaselineError(f"grouping relationship[{index}].sample_ids must be a non-empty string array")
        if members != sorted(set(members)):
            raise BaselineError(f"grouping relationship[{index}].sample_ids must be sorted and unique")
        if kind == "independent" and len(members) != 1:
            raise BaselineError("independent relationships must contain exactly one sample")
        unknown_members = set(members) - sample_ids
        if unknown_members:
            raise BaselineError(f"grouping relationship[{index}] references unknown samples")
        relationship = Relationship(kind, relationship_id, tuple(members))
        if relationship.qualified_id in qualified_ids:
            raise BaselineError(f"duplicate grouping relationship {relationship.qualified_id!r}")
        qualified_ids.add(relationship.qualified_id)
        covered.update(members)
        relationships.append(relationship)
    if covered != sample_ids:
        raise BaselineError(
            f"grouping sidecar must cover every sample: missing={sorted(sample_ids - covered)}, "
            f"unknown={sorted(covered - sample_ids)}"
        )
    normalized_authority = {
        "status": "authoritative",
        "source": authority["source"],
        "manifest_sha256": manifest_sha256,
    }
    return sorted(relationships, key=lambda item: item.qualified_id), normalized_authority, digest


def build_components(samples: list[Sample], relationships: list[Relationship]) -> list[Component]:
    """Collapse overlapping campaign/lineage relationships with union-find."""
    parents = {sample.sample_id: sample.sample_id for sample in samples}

    def find(sample_id: str) -> str:
        while parents[sample_id] != sample_id:
            parents[sample_id] = parents[parents[sample_id]]
            sample_id = parents[sample_id]
        return sample_id

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        first, second = sorted((left_root, right_root))
        parents[second] = first

    for relationship in relationships:
        anchor = relationship.sample_ids[0]
        for member in relationship.sample_ids[1:]:
            union(anchor, member)

    members_by_root: dict[str, list[str]] = {}
    for sample_id in sorted(parents):
        members_by_root.setdefault(find(sample_id), []).append(sample_id)
    sample_by_id = {sample.sample_id: sample for sample in samples}
    components: list[Component] = []
    for members in sorted(tuple(items) for items in members_by_root.values()):
        member_set = set(members)
        relation_ids = tuple(
            relationship.qualified_id
            for relationship in relationships
            if member_set.intersection(relationship.sample_ids)
        )
        digest = hashlib.sha256("\n".join(members).encode("utf-8")).hexdigest()[:16]
        components.append(
            Component(
                component_id=f"component-{digest}",
                sample_ids=members,
                relationship_ids=relation_ids,
                malicious_complete=sum(
                    sample_by_id[item].label == "malicious" and sample_by_id[item].coverage_status == "complete"
                    for item in members
                ),
                benign_complete=sum(
                    sample_by_id[item].label == "benign" and sample_by_id[item].coverage_status == "complete"
                    for item in members
                ),
            )
        )
    return components


def assign_folds(components: list[Component], *, requested_folds: int) -> list[list[Component]]:
    """Build nonempty, class-supported folds while keeping components whole."""
    fold_count = min(requested_folds, len(components))
    if fold_count < 2:
        return []
    malicious_components = sorted(
        (component for component in components if component.malicious_complete),
        key=lambda item: item.component_id,
    )
    benign_components = sorted(
        (component for component in components if component.benign_complete),
        key=lambda item: item.component_id,
    )
    if len(malicious_components) < 2 or len(benign_components) < 2:
        return []

    total_malicious = sum(component.malicious_complete for component in components)
    total_benign = sum(component.benign_complete for component in components)
    target_malicious = total_malicious / fold_count
    target_benign = total_benign / fold_count
    ordered = sorted(
        components,
        key=lambda item: (
            -len(item.sample_ids),
            -abs(item.malicious_complete - item.benign_complete),
            item.sample_ids,
        ),
    )
    required_by_id = {
        component.component_id: component for component in (*malicious_components[:2], *benign_components[:2])
    }
    required = [required_by_id[item] for item in sorted(required_by_id)]
    malicious_pair = tuple(component.component_id for component in malicious_components[:2])
    benign_pair = tuple(component.component_id for component in benign_components[:2])

    def counts_for(folds: list[list[Component]]) -> list[list[int]]:
        return [
            [
                sum(component.malicious_complete for component in fold),
                sum(component.benign_complete for component in fold),
            ]
            for fold in folds
        ]

    def loss_for(counts: list[list[int]]) -> float:
        return sum((malicious - target_malicious) ** 2 + (benign - target_benign) ** 2 for malicious, benign in counts)

    best_key: tuple[float, tuple[tuple[str, ...], ...]] | None = None
    best_folds: list[list[Component]] | None = None
    for placement in product(range(fold_count), repeat=len(required)):
        positions = {component.component_id: placement[index] for index, component in enumerate(required)}
        if positions[malicious_pair[0]] == positions[malicious_pair[1]]:
            continue
        if positions[benign_pair[0]] == positions[benign_pair[1]]:
            continue
        folds: list[list[Component]] = [[] for _ in range(fold_count)]
        for component, fold_index in zip(required, placement, strict=True):
            folds[fold_index].append(component)
        remaining = [component for component in ordered if component.component_id not in required_by_id]
        empty_folds = [index for index, fold in enumerate(folds) if not fold]
        if len(remaining) < len(empty_folds):
            continue
        for fold_index in empty_folds:
            folds[fold_index].append(remaining.pop(0))

        counts = counts_for(folds)
        for component in remaining:
            choices: list[tuple[float, int, int]] = []
            for fold_index in range(fold_count):
                projected = [list(item) for item in counts]
                projected[fold_index][0] += component.malicious_complete
                projected[fold_index][1] += component.benign_complete
                choices.append((loss_for(projected), sum(counts[fold_index]), fold_index))
            _, _, selected = min(choices)
            folds[selected].append(component)
            counts[selected][0] += component.malicious_complete
            counts[selected][1] += component.benign_complete

        normalized = [sorted(fold, key=lambda item: item.component_id) for fold in folds]
        signature = tuple(tuple(component.component_id for component in fold) for fold in normalized)
        key = (loss_for(counts_for(normalized)), signature)
        if best_key is None or key < best_key:
            best_key = key
            best_folds = normalized
    return best_folds or []


def train_model(samples: list[Sample], *, alpha: float) -> BernoulliModel:
    """Fit Bernoulli NB on complete training samples only."""
    complete = [sample for sample in samples if sample.coverage_status == "complete"]
    malicious = [sample for sample in complete if sample.label == "malicious"]
    benign = [sample for sample in complete if sample.label == "benign"]
    if not malicious or not benign:
        raise BaselineError("every fold training set must contain complete samples from both classes")
    vocabulary = tuple(sorted({rule_id for sample in complete for rule_id in sample.present_rule_ids}))
    probabilities: dict[str, tuple[float, float]] = {}
    for rule_id in vocabulary:
        malicious_count = sum(rule_id in sample.present_rule_ids for sample in malicious)
        benign_count = sum(rule_id in sample.present_rule_ids for sample in benign)
        probabilities[rule_id] = (
            (malicious_count + alpha) / (len(malicious) + 2 * alpha),
            (benign_count + alpha) / (len(benign) + 2 * alpha),
        )
    prior_log_odds = math.log(len(malicious) / len(complete)) - math.log(len(benign) / len(complete))
    return BernoulliModel(vocabulary, prior_log_odds, probabilities)


def _majority_label(samples: list[Sample]) -> Label:
    complete = [sample for sample in samples if sample.coverage_status == "complete"]
    malicious = sum(sample.label == "malicious" for sample in complete)
    benign = sum(sample.label == "benign" for sample in complete)
    return "malicious" if malicious > benign else "benign"


def _outcome(
    sample: Sample,
    *,
    predicted_label: Label | None,
    log_odds: float | None,
    contributions: list[dict[str, object]],
) -> dict[str, object]:
    abstained = predicted_label is None
    if predicted_label is None:
        penalized_prediction: Label = "benign" if sample.label == "malicious" else "malicious"
    else:
        penalized_prediction = predicted_label
    return {
        "sample_id": sample.sample_id,
        "label": sample.label,
        "coverage_status": sample.coverage_status,
        "decision": "abstain" if abstained else predicted_label,
        "penalized_prediction": penalized_prediction,
        "malicious_log_odds": log_odds,
        "feature_contributions": contributions,
    }


def compute_metrics(outcomes: list[dict[str, object]]) -> dict[str, int | float | None]:
    """Compute conservative metrics, counting abstentions as class-opposite errors."""
    tp = fp = fn = tn = abstentions = 0
    for outcome in outcomes:
        label = outcome["label"]
        prediction = outcome["penalized_prediction"]
        if outcome["decision"] == "abstain":
            abstentions += 1
        if label == "malicious" and prediction == "malicious":
            tp += 1
        elif label == "malicious":
            fn += 1
        elif prediction == "malicious":
            fp += 1
        else:
            tn += 1
    total = len(outcomes)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    false_positive_rate = fp / (fp + tn) if fp + tn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
    )
    balanced_accuracy = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else None
    return {
        "samples": total,
        "positive": tp + fn,
        "negative": tn + fp,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "abstentions": abstentions,
        "abstention_rate": abstentions / total if total else 0.0,
        "coverage_failures": abstentions,
        "coverage_failure_rate": abstentions / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "false_positive_rate": false_positive_rate,
        "balanced_accuracy": balanced_accuracy,
        "matthews_correlation_coefficient": mcc,
    }


def _metric_ranges(folds: list[dict[str, Any]], *, key: str) -> dict[str, dict[str, float] | None]:
    ranges: dict[str, dict[str, float] | None] = {}
    for field in METRIC_RANGE_FIELDS:
        values = [fold[key][field] for fold in folds if isinstance(fold[key][field], (int, float))]
        ranges[field] = {"min": min(values), "max": max(values)} if values else None
    return ranges


def _not_evaluated_report(
    *,
    config: BaselineConfig,
    feature_provenance: dict[str, Any],
    feature_artifact_sha256: str,
    config_sha256: str,
    reason: str,
    grouping_sidecar_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "not-evaluated",
        "purpose": "research-only-interpretable-baseline",
        "reason_codes": [reason],
        "configuration": config.to_dict(),
        "provenance": {
            "feature_artifact_sha256": feature_artifact_sha256,
            "feature_contract_sha256": feature_provenance.get("feature_contract_sha256"),
            "config_sha256": config_sha256,
            "grouping_sidecar_sha256": grouping_sidecar_sha256,
            "baseline_source_sha256": _sha256(Path(__file__).resolve()),
            "baseline_report_schema_sha256": _schema_sha256("baseline_report.schema.json"),
            "baseline_config_schema_sha256": _schema_sha256("baseline_config.schema.json"),
            "benchmark_groups_schema_sha256": _schema_sha256("benchmark_groups.schema.json"),
        },
        "grouping": None,
        "metrics": None,
        "folds": [],
        "limitations": _limitations(),
    }


def _limitations() -> list[str]:
    return [
        "Research diagnostic only; this is not a deployable malicious-skill classifier.",
        "The model observes only eligible binary detector-rule presence.",
        "Performance estimates are meaningful only for the supplied authoritative grouping and corpus.",
        "Static coverage failures abstain and are conservatively counted as errors.",
    ]


def evaluate_baseline(
    features_path: Path,
    config_path: Path,
    groups_path: Path | None,
) -> dict[str, Any]:
    """Evaluate the fixed baseline or return an honest not-evaluated report."""
    features_path = features_path.resolve()
    config_path = config_path.resolve()
    config, config_sha256 = _load_config_with_sha256(config_path)
    samples, feature_provenance, feature_artifact_sha256 = load_feature_artifact(features_path)
    if groups_path is None:
        return _not_evaluated_report(
            config=config,
            feature_provenance=feature_provenance,
            feature_artifact_sha256=feature_artifact_sha256,
            config_sha256=config_sha256,
            reason="authoritative-grouping-unavailable",
        )

    groups_path = groups_path.resolve()
    manifest_sha256 = feature_provenance.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or not SHA256_RE.fullmatch(manifest_sha256):
        raise BaselineError("feature artifact provenance has no valid manifest_sha256")
    relationships, authority, grouping_sidecar_sha256 = load_relationships(
        groups_path,
        sample_ids={sample.sample_id for sample in samples},
        expected_manifest_sha256=manifest_sha256,
    )
    components = build_components(samples, relationships)
    assigned = assign_folds(components, requested_folds=config.folds)
    if not assigned or any(not fold for fold in assigned):
        return _not_evaluated_report(
            config=config,
            feature_provenance=feature_provenance,
            feature_artifact_sha256=feature_artifact_sha256,
            config_sha256=config_sha256,
            reason="insufficient-group-disjoint-fold-support",
            grouping_sidecar_sha256=grouping_sidecar_sha256,
        )

    sample_by_id = {sample.sample_id: sample for sample in samples}
    all_ids = set(sample_by_id)
    fold_reports: list[dict[str, Any]] = []
    all_model_outcomes: list[dict[str, object]] = []
    all_majority_outcomes: list[dict[str, object]] = []
    for fold_index, held_components in enumerate(assigned):
        test_ids = {sample_id for component in held_components for sample_id in component.sample_ids}
        train = [sample_by_id[sample_id] for sample_id in sorted(all_ids - test_ids)]
        test = [sample_by_id[sample_id] for sample_id in sorted(test_ids)]
        try:
            model = train_model(train, alpha=config.alpha)
        except BaselineError:
            return _not_evaluated_report(
                config=config,
                feature_provenance=feature_provenance,
                feature_artifact_sha256=feature_artifact_sha256,
                config_sha256=config_sha256,
                reason="insufficient-complete-class-support-per-fold",
                grouping_sidecar_sha256=grouping_sidecar_sha256,
            )
        majority = _majority_label(train)
        model_outcomes: list[dict[str, object]] = []
        majority_outcomes: list[dict[str, object]] = []
        for sample in test:
            if sample.coverage_status != "complete":
                model_outcomes.append(_outcome(sample, predicted_label=None, log_odds=None, contributions=[]))
                majority_outcomes.append(_outcome(sample, predicted_label=None, log_odds=None, contributions=[]))
                continue
            log_odds, contributions = model.score(sample.present_rule_ids)
            prediction: Label = "malicious" if log_odds > config.decision_threshold else "benign"
            model_outcomes.append(
                _outcome(sample, predicted_label=prediction, log_odds=log_odds, contributions=contributions)
            )
            majority_outcomes.append(_outcome(sample, predicted_label=majority, log_odds=None, contributions=[]))
        all_model_outcomes.extend(model_outcomes)
        all_majority_outcomes.extend(majority_outcomes)
        train_complete = [sample for sample in train if sample.coverage_status == "complete"]
        fold_reports.append(
            {
                "fold": fold_index,
                "held_out_component_ids": [component.component_id for component in held_components],
                "train_support": {
                    "samples": len(train),
                    "complete": len(train_complete),
                    "malicious_complete": sum(sample.label == "malicious" for sample in train_complete),
                    "benign_complete": sum(sample.label == "benign" for sample in train_complete),
                },
                "test_support": {
                    "samples": len(test),
                    "malicious": sum(sample.label == "malicious" for sample in test),
                    "benign": sum(sample.label == "benign" for sample in test),
                },
                "model": {
                    "prior_log_odds": model.prior_log_odds,
                    "vocabulary": list(model.vocabulary),
                    "feature_parameters": model.audit_parameters(),
                },
                "majority_training_label": majority,
                "bernoulli_nb_metrics": compute_metrics(model_outcomes),
                "majority_metrics": compute_metrics(majority_outcomes),
                "bernoulli_nb_predictions": model_outcomes,
                "majority_predictions": majority_outcomes,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "evaluated",
        "purpose": "research-only-interpretable-baseline",
        "reason_codes": [],
        "configuration": config.to_dict(),
        "provenance": {
            "feature_artifact_sha256": feature_artifact_sha256,
            "feature_contract_sha256": feature_provenance.get("feature_contract_sha256"),
            "config_sha256": config_sha256,
            "grouping_sidecar_sha256": grouping_sidecar_sha256,
            "baseline_source_sha256": _sha256(Path(__file__).resolve()),
            "baseline_report_schema_sha256": _schema_sha256("baseline_report.schema.json"),
            "baseline_config_schema_sha256": _schema_sha256("baseline_config.schema.json"),
            "benchmark_groups_schema_sha256": _schema_sha256("benchmark_groups.schema.json"),
        },
        "grouping": {
            "authority": authority,
            "relationship_count": len(relationships),
            "component_count": len(components),
            "requested_folds": config.folds,
            "used_folds": len(assigned),
            "components": [
                {
                    "component_id": component.component_id,
                    "sample_ids": list(component.sample_ids),
                    "relationship_ids": list(component.relationship_ids),
                }
                for component in components
            ],
        },
        "metrics": {
            "bernoulli_nb": compute_metrics(all_model_outcomes),
            "majority": compute_metrics(all_majority_outcomes),
            "bernoulli_nb_fold_ranges": _metric_ranges(fold_reports, key="bernoulli_nb_metrics"),
            "majority_fold_ranges": _metric_ranges(fold_reports, key="majority_metrics"),
        },
        "folds": fold_reports,
        "limitations": _limitations(),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Razin detector features with a grouped reference baseline")
    parser.add_argument("--features", required=True, type=Path, help="Detector feature artifact")
    parser.add_argument("--groups", type=Path, help="Authoritative campaign/lineage relationship sidecar")
    parser.add_argument("--config", required=True, type=Path, help="Fixed baseline configuration")
    parser.add_argument("--output", required=True, type=Path, help="Write the baseline report to this path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        report = evaluate_baseline(args.features, args.config, args.groups)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"baseline status: {report['status']}")
        for reason in report["reason_codes"]:
            print(f"reason: {reason}")
        return 0
    except (BaselineError, OSError) as exc:
        print(f"Baseline error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
