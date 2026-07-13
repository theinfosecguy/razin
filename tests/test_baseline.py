from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

import scripts.evaluate_baseline as baseline_module
from scripts.evaluate_baseline import (
    BaselineError,
    Component,
    Sample,
    assign_folds,
    compute_metrics,
    evaluate_baseline,
    load_config,
    train_model,
)
from scripts.evaluate_corpus import build_feature_artifact, evaluate

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "benchmarks/baselines/bernoulli-nb-v1.json"
GROUPS_PATH = REPO_ROOT / "benchmarks/synthetic/groups.json"


def _write_json(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def feature_artifact(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    artifact = build_feature_artifact(evaluate(REPO_ROOT / "benchmarks/synthetic/manifest.json"))
    return _write_json(tmp_path / "features.json", artifact), artifact


def test_versioned_baseline_inputs_validate_and_bind_the_synthetic_manifest() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    groups = json.loads(GROUPS_PATH.read_text(encoding="utf-8"))
    config_schema = json.loads((REPO_ROOT / "schemas/v1/baseline_config.schema.json").read_text(encoding="utf-8"))
    groups_schema = json.loads((REPO_ROOT / "schemas/v1/benchmark_groups.schema.json").read_text(encoding="utf-8"))

    jsonschema.validate(config, config_schema)
    jsonschema.validate(groups, groups_schema)
    expected_manifest_sha = hashlib.sha256((REPO_ROOT / "benchmarks/synthetic/manifest.json").read_bytes()).hexdigest()
    assert groups["authority"]["manifest_sha256"] == expected_manifest_sha


@pytest.mark.parametrize(
    "schema_name",
    ("baseline_config.schema.json", "baseline_report.schema.json", "benchmark_groups.schema.json"),
)
def test_root_baseline_schema_matches_immutable_v1(schema_name: str) -> None:
    latest = json.loads((REPO_ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    versioned = json.loads((REPO_ROOT / "schemas/v1" / schema_name).read_text(encoding="utf-8"))
    latest["$id"] = versioned["$id"]

    assert latest == versioned


def test_grouped_baseline_is_deterministic_schema_valid_and_worse_than_majority(
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    feature_path, _ = feature_artifact

    first = evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)
    second = evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)

    assert first == second
    schema = json.loads((REPO_ROOT / "schemas/v1/baseline_report.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(first, schema)
    assert first["status"] == "evaluated"
    assert (
        first["provenance"]["baseline_report_schema_sha256"]
        == hashlib.sha256((REPO_ROOT / "schemas/v1/baseline_report.schema.json").read_bytes()).hexdigest()
    )
    assert first["grouping"]["component_count"] == 6
    assert first["grouping"]["used_folds"] == 3
    assert first["metrics"]["bernoulli_nb"]["recall"] == 0.0
    assert first["metrics"]["bernoulli_nb"]["balanced_accuracy"] < first["metrics"]["majority"]["balanced_accuracy"]


def test_each_fold_uses_only_training_vocabulary_and_holds_out_whole_components(
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    feature_path, artifact = feature_artifact
    report = evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)
    samples = {sample["metadata"]["id"]: sample for sample in artifact["samples"]}
    component_members = {
        component["component_id"]: set(component["sample_ids"]) for component in report["grouping"]["components"]
    }
    predicted_ids: list[str] = []

    for fold in report["folds"]:
        test_ids = set().union(*(component_members[item] for item in fold["held_out_component_ids"]))
        train_ids = set(samples) - test_ids
        expected_vocabulary = sorted(
            {
                rule_id
                for sample_id in train_ids
                if samples[sample_id]["metadata"]["coverage_status"] == "complete"
                for rule_id in samples[sample_id]["features"]["present_rule_ids"]
            }
        )
        assert fold["model"]["vocabulary"] == expected_vocabulary
        fold_predictions = fold["bernoulli_nb_predictions"]
        assert {prediction["sample_id"] for prediction in fold_predictions} == test_ids
        predicted_ids.extend(prediction["sample_id"] for prediction in fold_predictions)
        for prediction in fold_predictions:
            if prediction["decision"] != "abstain":
                assert [item["rule_id"] for item in prediction["feature_contributions"]] == expected_vocabulary

    assert sorted(predicted_ids) == sorted(samples)


def test_missing_authoritative_groups_is_not_evaluated(
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    feature_path, _ = feature_artifact

    report = evaluate_baseline(feature_path, CONFIG_PATH, None)

    schema = json.loads((REPO_ROOT / "schemas/v1/baseline_report.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(report, schema)
    assert report["status"] == "not-evaluated"
    assert report["reason_codes"] == ["authoritative-grouping-unavailable"]
    assert report["metrics"] is None
    assert report["grouping"] is None


def test_overlapping_campaign_and_lineage_relationships_form_one_component(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    feature_path, _ = feature_artifact
    groups = json.loads(GROUPS_PATH.read_text(encoding="utf-8"))
    groups["relationships"][0]["sample_ids"] = [
        "malicious-data-exfiltration",
        "malicious-prompt-injection",
    ]
    groups_path = _write_json(tmp_path / "overlap.json", groups)

    report = evaluate_baseline(feature_path, CONFIG_PATH, groups_path)

    containing = [
        component
        for component in report["grouping"]["components"]
        if "malicious-data-exfiltration" in component["sample_ids"]
    ]
    assert len(containing) == 1
    assert set(containing[0]["sample_ids"]) == {
        "malicious-data-exfiltration",
        "malicious-prompt-injection",
    }


def test_incomplete_coverage_abstains_and_counts_as_an_error(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    _, artifact = feature_artifact
    changed = copy.deepcopy(artifact)
    sample = next(item for item in changed["samples"] if item["metadata"]["id"] == "benign-oauth-client")
    sample["metadata"]["coverage_status"] = "incomplete"
    feature_path = _write_json(tmp_path / "incomplete.json", changed)

    report = evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)

    metrics = report["metrics"]["bernoulli_nb"]
    assert metrics["abstentions"] == 1
    assert metrics["coverage_failures"] == 1
    abstention = next(
        prediction
        for fold in report["folds"]
        for prediction in fold["bernoulli_nb_predictions"]
        if prediction["sample_id"] == "benign-oauth-client"
    )
    assert abstention["decision"] == "abstain"
    assert abstention["penalized_prediction"] == "malicious"


def test_modified_embedded_feature_contract_is_rejected(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    _, artifact = feature_artifact
    changed = copy.deepcopy(artifact)
    changed["contract"]["unknown_rule_policy"]["exclusion_reason"] = "tampered"
    feature_path = _write_json(tmp_path / "tampered-contract.json", changed)

    with pytest.raises(BaselineError, match="modified or unsupported feature contract"):
        evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)


def test_integer_cannot_impersonate_boolean_feature_eligibility(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    _, artifact = feature_artifact
    changed = copy.deepcopy(artifact)
    sample = next(item for item in changed["samples"] if item["features"]["present_rule_ids"])
    eligible = next(rule for rule in sample["audit"]["rules"] if rule["model_eligible"] is True)
    eligible["model_eligible"] = 1
    feature_path = _write_json(tmp_path / "integer-eligibility.json", changed)

    with pytest.raises(BaselineError, match="contradicts the feature contract"):
        evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)


def test_feature_vector_that_disagrees_with_audit_is_rejected(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    _, artifact = feature_artifact
    changed = copy.deepcopy(artifact)
    sample = next(item for item in changed["samples"] if item["features"]["present_rule_ids"])
    sample["features"]["present_rule_ids"] = []
    feature_path = _write_json(tmp_path / "tampered-vector.json", changed)

    with pytest.raises(BaselineError, match="exactly match eligible audit rules"):
        evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)


def test_grouping_must_be_authoritative_and_cover_every_sample(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    feature_path, _ = feature_artifact
    groups = json.loads(GROUPS_PATH.read_text(encoding="utf-8"))
    groups["authority"]["status"] = "diagnostic"
    path = _write_json(tmp_path / "diagnostic.json", groups)
    with pytest.raises(BaselineError, match="explicitly be authoritative"):
        evaluate_baseline(feature_path, CONFIG_PATH, path)

    groups = json.loads(GROUPS_PATH.read_text(encoding="utf-8"))
    groups["relationships"] = groups["relationships"][:-1]
    path = _write_json(tmp_path / "incomplete-groups.json", groups)
    with pytest.raises(BaselineError, match="cover every sample"):
        evaluate_baseline(feature_path, CONFIG_PATH, path)

    groups = json.loads(GROUPS_PATH.read_text(encoding="utf-8"))
    groups["authority"]["manifest_sha256"] = "0" * 64
    path = _write_json(tmp_path / "wrong-manifest.json", groups)
    with pytest.raises(BaselineError, match="not bound to the feature artifact manifest"):
        evaluate_baseline(feature_path, CONFIG_PATH, path)


def test_reference_configuration_rejects_tuning(tmp_path: Path) -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config["alpha"] = 0.5
    path = _write_json(tmp_path / "tuned.json", config)

    with pytest.raises(BaselineError, match="alpha must be exactly 1.0"):
        load_config(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("alpha", True, "alpha must be exactly 1.0"),
        ("decision_threshold", False, "decision_threshold must be exactly 0.0"),
        ("folds", 4, "folds must be exactly 3"),
    ),
)
def test_reference_configuration_rejects_numeric_contract_changes(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config[field] = value
    path = _write_json(tmp_path / f"boolean-{field}.json", config)

    with pytest.raises(BaselineError, match=message):
        load_config(path)


def test_input_provenance_hashes_the_exact_bytes_that_were_parsed(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feature_path, artifact = feature_artifact
    original_bytes = feature_path.read_bytes()
    replacement = copy.deepcopy(artifact)
    replacement["benchmark"] = "concurrently-replaced"
    original_reader = baseline_module._read_json

    def replacing_reader(path: Path, *, name: str) -> tuple[dict[str, Any], str]:
        parsed, digest = original_reader(path, name=name)
        if path == feature_path:
            _write_json(path, replacement)
        return parsed, digest

    monkeypatch.setattr(baseline_module, "_read_json", replacing_reader)

    report = evaluate_baseline(feature_path, CONFIG_PATH, GROUPS_PATH)

    assert report["provenance"]["feature_artifact_sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert report["provenance"]["feature_artifact_sha256"] != hashlib.sha256(feature_path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "counts",
    (
        ((1, 0), (0, 1), (1, 1)),
        ((0, 2), (1, 1), (2, 0)),
    ),
)
def test_fold_assignment_finds_valid_class_supported_partition(
    counts: tuple[tuple[int, int], ...],
) -> None:
    components = [
        Component(
            component_id=f"component-{index}",
            sample_ids=(f"sample-{index}",),
            relationship_ids=(f"independent:{index}",),
            malicious_complete=malicious,
            benign_complete=benign,
        )
        for index, (malicious, benign) in enumerate(counts)
    ]

    folds = assign_folds(components, requested_folds=2)

    assert len(folds) == 2
    assert all(fold for fold in folds)
    total_malicious = sum(component.malicious_complete for component in components)
    total_benign = sum(component.benign_complete for component in components)
    for held_out in folds:
        assert sum(component.malicious_complete for component in held_out) < total_malicious
        assert sum(component.benign_complete for component in held_out) < total_benign


def test_fold_assignment_never_leaves_a_fold_empty() -> None:
    components = [
        Component("component-a", ("a",), ("campaign:a",), 1, 0),
        Component("component-b", ("b",), ("campaign:b",), 2, 1),
        Component("component-c", ("c",), ("independent:c",), 0, 1),
    ]

    folds = assign_folds(components, requested_folds=3)

    assert len(folds) == 3
    assert all(len(fold) == 1 for fold in folds)


def test_insufficient_group_disjoint_training_support_is_not_evaluated(
    tmp_path: Path,
    feature_artifact: tuple[Path, dict[str, Any]],
) -> None:
    feature_path, _ = feature_artifact
    groups = json.loads(GROUPS_PATH.read_text(encoding="utf-8"))
    malicious_ids = [
        "malicious-data-exfiltration",
        "malicious-prompt-injection",
        "malicious-remote-code-execution",
    ]
    groups["relationships"] = [
        {
            "kind": "campaign",
            "id": "all-malicious-related",
            "sample_ids": malicious_ids,
        },
        *[relationship for relationship in groups["relationships"] if relationship["kind"] == "independent"],
    ]
    path = _write_json(tmp_path / "unsupported-folds.json", groups)

    report = evaluate_baseline(feature_path, CONFIG_PATH, path)

    assert report["status"] == "not-evaluated"
    assert report["reason_codes"] == ["insufficient-group-disjoint-fold-support"]
    assert report["provenance"]["grouping_sidecar_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_ties_are_benign_and_vocabulary_comes_only_from_training() -> None:
    model = train_model(
        [
            Sample("malicious", "malicious", "complete", frozenset({"SHARED"})),
            Sample("benign", "benign", "complete", frozenset({"SHARED"})),
        ],
        alpha=1.0,
    )

    log_odds, _ = model.score(frozenset({"HELD_OUT_ONLY"}))

    assert model.vocabulary == ("SHARED",)
    assert log_odds == 0.0
    assert not (log_odds > 0.0)


def test_metrics_penalize_both_classes_of_abstention() -> None:
    metrics = compute_metrics(
        [
            {
                "label": "malicious",
                "decision": "abstain",
                "penalized_prediction": "benign",
            },
            {
                "label": "benign",
                "decision": "abstain",
                "penalized_prediction": "malicious",
            },
        ]
    )

    assert metrics["false_negative"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["abstentions"] == 2
    assert metrics["balanced_accuracy"] == 0.0
