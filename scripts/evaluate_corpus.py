#!/usr/bin/env python3
"""Evaluate package-level block and review outcomes against a labeled corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from razin import __version__
from razin.config import load_config
from razin.model import Finding
from razin.parsers import parse_skill_markdown_file
from razin.scanner import scan_workspace
from razin.scanner.assessment import evidence_verdict_for_package
from razin.scanner.discovery import assign_unique_skill_names, discover_skill_files

MANIFEST_SCHEMA_VERSION = "2.0"
GATE_SCHEMA_VERSION = "3.0"
REPORT_SCHEMA_VERSION = "3.0"
LABELS = frozenset({"benign", "malicious"})
OUTCOMES = ("block", "review")
METRIC_GATE_KEYS = frozenset(
    {
        "min_samples",
        "min_positive",
        "min_negative",
        "min_precision",
        "min_recall",
        "min_f1",
        "min_specificity",
        "max_false_positive_rate",
        "max_coverage_failure_rate",
    }
)


class BenchmarkError(Exception):
    """Raised for invalid benchmark input or an unsafe evaluation setup."""


def _load_json_object(path: Path, *, kind: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"Cannot load {kind} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BenchmarkError(f"{kind.capitalize()} must be a JSON object: {path}")
    return payload


def _require_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkError(f"{field} must be a non-empty string")
    return value.strip()


def _string_list(value: object, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise BenchmarkError(f"{field} must be an array of non-empty strings")
    return value


def _resolve_manifest(manifest_path: Path) -> tuple[dict[str, Any], Path, list[dict[str, Any]]]:
    manifest = _load_json_object(manifest_path, kind="manifest")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise BenchmarkError(f"manifest.schema_version must be {MANIFEST_SCHEMA_VERSION!r}")

    root_value = _require_string(manifest.get("corpus_root", "."), field="manifest.corpus_root")
    corpus_root = Path(root_value)
    if not corpus_root.is_absolute():
        corpus_root = manifest_path.parent / corpus_root
    corpus_root = corpus_root.resolve()
    if not corpus_root.is_dir():
        raise BenchmarkError(f"Corpus root does not exist or is not a directory: {corpus_root}")

    raw_samples = manifest.get("samples")
    if not isinstance(raw_samples, list) or not raw_samples:
        raise BenchmarkError("manifest.samples must be a non-empty array")

    samples: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_paths: set[Path] = set()
    for index, raw_sample in enumerate(raw_samples):
        prefix = f"manifest.samples[{index}]"
        if not isinstance(raw_sample, dict):
            raise BenchmarkError(f"{prefix} must be an object")
        sample_id = _require_string(raw_sample.get("id"), field=f"{prefix}.id")
        label = _require_string(raw_sample.get("label"), field=f"{prefix}.label").lower()
        family = _require_string(raw_sample.get("family", "unlabeled"), field=f"{prefix}.family")
        diagnostic_group = raw_sample.get("diagnostic_group")
        if diagnostic_group is not None:
            diagnostic_group = _require_string(diagnostic_group, field=f"{prefix}.diagnostic_group")
        path_value = _require_string(raw_sample.get("path"), field=f"{prefix}.path")
        if label not in LABELS:
            raise BenchmarkError(f"{prefix}.label must be one of: {', '.join(sorted(LABELS))}")
        if sample_id in seen_ids:
            raise BenchmarkError(f"Duplicate sample id: {sample_id}")

        skill_path = (corpus_root / path_value).resolve()
        if skill_path.is_dir():
            skill_path /= "SKILL.md"
        try:
            relative_path = skill_path.relative_to(corpus_root)
        except ValueError as exc:
            raise BenchmarkError(f"Sample path escapes corpus root: {path_value}") from exc
        if not skill_path.is_file() or skill_path.name != "SKILL.md":
            raise BenchmarkError(f"Sample does not resolve to a SKILL.md file: {path_value}")
        if skill_path in seen_paths:
            raise BenchmarkError(f"Duplicate sample path: {relative_path.as_posix()}")

        expected_rule_ids = _string_list(raw_sample.get("expected_rule_ids"), field=f"{prefix}.expected_rule_ids")
        expected_block = raw_sample.get("expected_block")
        expected_review = raw_sample.get("expected_review")
        for field, value in (("expected_block", expected_block), ("expected_review", expected_review)):
            if value is not None and not isinstance(value, bool):
                raise BenchmarkError(f"{prefix}.{field} must be a boolean")

        seen_ids.add(sample_id)
        seen_paths.add(skill_path)
        samples.append(
            {
                "id": sample_id,
                "label": label,
                "family": family,
                "diagnostic_group": diagnostic_group,
                "path": relative_path.as_posix(),
                "expected_rule_ids": expected_rule_ids,
                "expected_block": expected_block,
                "expected_review": expected_review,
            }
        )
    inventory = manifest.get("inventory")
    if inventory is not None:
        if not isinstance(inventory, dict):
            raise BenchmarkError("manifest.inventory must be an object")
        observed = {label: sum(sample["label"] == label for sample in samples) for label in LABELS}
        for label in LABELS:
            expected = inventory.get(label)
            if not isinstance(expected, int) or isinstance(expected, bool) or expected != observed[label]:
                raise BenchmarkError(f"manifest.inventory.{label} expected {expected!r}, observed {observed[label]}")
    return manifest, corpus_root, samples


def _scanner_options(manifest: dict[str, Any], manifest_path: Path, corpus_root: Path) -> dict[str, Any]:
    raw = manifest.get("scanner", {})
    if not isinstance(raw, dict):
        raise BenchmarkError("manifest.scanner must be an object")
    allowed = {"profile", "max_file_mb", "config", "disable_rules", "only_rules"}
    unknown = set(raw) - allowed
    if unknown:
        raise BenchmarkError(f"Unknown manifest.scanner fields: {', '.join(sorted(unknown))}")

    profile = raw.get("profile")
    if profile is not None and profile not in {"strict", "balanced", "audit"}:
        raise BenchmarkError("manifest.scanner.profile must be strict, balanced, or audit")
    max_file_mb = raw.get("max_file_mb")
    if max_file_mb is not None and (
        not isinstance(max_file_mb, int) or isinstance(max_file_mb, bool) or max_file_mb < 1
    ):
        raise BenchmarkError("manifest.scanner.max_file_mb must be a positive integer")

    config_path: Path | None = None
    if raw.get("config") is not None:
        config_value = _require_string(raw["config"], field="manifest.scanner.config")
        config_path = Path(config_value)
        if not config_path.is_absolute():
            config_path = manifest_path.parent / config_path
        config_path = config_path.resolve()
        if not config_path.is_file():
            raise BenchmarkError(f"Trusted benchmark config does not exist: {config_path}")
        try:
            config_path.relative_to(corpus_root)
        except ValueError:
            pass
        else:
            raise BenchmarkError("manifest.scanner.config must be outside the untrusted corpus root")

    disable_rules = tuple(_string_list(raw.get("disable_rules", []), field="manifest.scanner.disable_rules"))
    only_rules = tuple(_string_list(raw.get("only_rules", []), field="manifest.scanner.only_rules"))
    if disable_rules and only_rules:
        raise BenchmarkError("manifest.scanner.disable_rules and only_rules are mutually exclusive")
    return {
        "profile": profile,
        "max_file_mb": max_file_mb,
        "config_path": config_path,
        "disable_rules": disable_rules,
        "only_rules": only_rules,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def compute_metrics(outcomes: list[dict[str, Any]], prediction_key: str = "block_positive") -> dict[str, Any]:
    """Compute a complete confusion matrix while penalizing coverage failures."""
    coverage_statuses = [
        item.get("coverage_status", "incomplete" if item.get("incomplete", False) else "complete") for item in outcomes
    ]
    coverage_failures = [status != "complete" for status in coverage_statuses]
    tp = sum(
        item["label"] == "malicious" and item[prediction_key] and not failed
        for item, failed in zip(outcomes, coverage_failures, strict=True)
    )
    fp = sum(
        item["label"] == "benign" and (item[prediction_key] or failed)
        for item, failed in zip(outcomes, coverage_failures, strict=True)
    )
    fn = sum(
        item["label"] == "malicious" and (not item[prediction_key] or failed)
        for item, failed in zip(outcomes, coverage_failures, strict=True)
    )
    tn = sum(
        item["label"] == "benign" and not item[prediction_key] and not failed
        for item, failed in zip(outcomes, coverage_failures, strict=True)
    )
    incomplete = sum(status == "incomplete" for status in coverage_statuses)
    not_evaluated = sum(status == "not-evaluated" for status in coverage_statuses)
    coverage_failure = sum(coverage_failures)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None:
        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "samples": len(outcomes),
        "positive": tp + fn,
        "negative": tn + fp,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "incomplete": incomplete,
        "incomplete_rate": _ratio(incomplete, len(outcomes)),
        "not_evaluated": not_evaluated,
        "not_evaluated_rate": _ratio(not_evaluated, len(outcomes)),
        "coverage_failure": coverage_failure,
        "coverage_failure_rate": _ratio(coverage_failure, len(outcomes)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": _ratio(tn, tn + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
    }


def _validate_enforced_gates(gates: dict[str, Any], *, authoritative_families: bool) -> None:
    if gates.get("status") != "enforced":
        return
    required = {
        "min_samples",
        "min_positive",
        "min_negative",
        "min_precision",
        "min_recall",
        "max_coverage_failure_rate",
    }

    def validate_scope(scope_name: str, scope: object) -> None:
        if not isinstance(scope, dict):
            raise BenchmarkError(f"enforced gates require {scope_name}")
        missing = required - set(scope)
        if missing:
            raise BenchmarkError(f"enforced {scope_name} gates omit: {', '.join(sorted(missing))}")
        if not {"min_specificity", "max_false_positive_rate"}.intersection(scope):
            raise BenchmarkError(f"enforced {scope_name} requires min_specificity or max_false_positive_rate")
        for key in ("min_samples", "min_positive", "min_negative"):
            value = scope[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise BenchmarkError(f"enforced {scope_name}.{key} must be an integer of at least one")
        if (
            not isinstance(scope["min_precision"], (int, float))
            or isinstance(scope["min_precision"], bool)
            or scope["min_precision"] < 0.5
        ):
            raise BenchmarkError(f"enforced {scope_name}.min_precision must be at least 0.5")
        if (
            not isinstance(scope["min_recall"], (int, float))
            or isinstance(scope["min_recall"], bool)
            or scope["min_recall"] < 0.1
        ):
            raise BenchmarkError(f"enforced {scope_name}.min_recall must be at least 0.1")
        if (
            not isinstance(scope["max_coverage_failure_rate"], (int, float))
            or isinstance(scope["max_coverage_failure_rate"], bool)
            or not 0 <= scope["max_coverage_failure_rate"] < 0.25
        ):
            raise BenchmarkError(f"enforced {scope_name}.max_coverage_failure_rate must be in [0, 0.25)")
        if "max_false_positive_rate" in scope and (
            not isinstance(scope["max_false_positive_rate"], (int, float))
            or not 0 <= scope["max_false_positive_rate"] < 0.5
        ):
            raise BenchmarkError(f"enforced {scope_name}.max_false_positive_rate must be in [0, 0.5)")
        if "min_specificity" in scope and (
            not isinstance(scope["min_specificity"], (int, float)) or scope["min_specificity"] < 0.5
        ):
            raise BenchmarkError(f"enforced {scope_name}.min_specificity must be at least 0.5")

    for outcome in OUTCOMES:
        configured = gates.get(outcome)
        if not isinstance(configured, dict):
            raise BenchmarkError(f"enforced gates require {outcome}")
        validate_scope(f"{outcome}.overall", configured.get("overall"))
        families = configured.get("families", {})
        if not isinstance(families, dict):
            raise BenchmarkError(f"gates.{outcome}.families must be an object")
        if families and not authoritative_families:
            raise BenchmarkError("family gates require an authoritative manifest family mapping")
        for family, scope in families.items():
            validate_scope(f"{outcome}.families.{family}", scope)


def _evaluate_gates(
    metrics: dict[str, dict[str, Any]],
    family_metrics: dict[str, dict[str, dict[str, Any]]],
    gates_path: Path | None,
    *,
    authoritative_families: bool,
) -> tuple[dict[str, Any] | None, list[str]]:
    if gates_path is None:
        return None, []
    gates = _load_json_object(gates_path, kind="gates")
    if gates.get("schema_version") != GATE_SCHEMA_VERSION:
        raise BenchmarkError(f"gates.schema_version must be {GATE_SCHEMA_VERSION!r}")
    _validate_enforced_gates(gates, authoritative_families=authoritative_families)
    if gates.get("status") != "enforced":
        return gates, ["gates.status: thresholds are not reviewed and enforced"]

    failures: list[str] = []
    field_map = {
        "min_samples": "samples",
        "min_positive": "positive",
        "min_negative": "negative",
        "min_precision": "precision",
        "min_recall": "recall",
        "min_f1": "f1",
        "min_specificity": "specificity",
        "max_false_positive_rate": "false_positive_rate",
        "max_coverage_failure_rate": "coverage_failure_rate",
    }

    def check(scope: str, actual: dict[str, Any], configured: object) -> None:
        if not isinstance(configured, dict):
            raise BenchmarkError(f"Gate scope {scope} must be an object")
        unknown = set(configured) - METRIC_GATE_KEYS
        if unknown:
            raise BenchmarkError(f"Unknown gate fields in {scope}: {', '.join(sorted(unknown))}")
        for gate_name, expected in configured.items():
            if not isinstance(expected, (int, float)) or isinstance(expected, bool):
                raise BenchmarkError(f"Gate {scope}.{gate_name} must be numeric")
            metric_name = field_map[gate_name]
            observed = actual.get(metric_name)
            if observed is None:
                failures.append(f"{scope}.{gate_name}: metric {metric_name} is undefined")
                continue
            passed = observed <= expected if gate_name.startswith("max_") else observed >= expected
            if not passed:
                operator = "<=" if gate_name.startswith("max_") else ">="
                failures.append(f"{scope}.{gate_name}: observed {observed:.6g}, required {operator} {expected:.6g}")

    for outcome in OUTCOMES:
        configured = gates[outcome]
        check(f"{outcome}.overall", metrics[outcome], configured["overall"])
        families = configured.get("families", {})
        if not isinstance(families, dict):
            raise BenchmarkError(f"gates.{outcome}.families must be an object")
        for family, family_gates in sorted(families.items()):
            actual = family_metrics.get(family, {}).get(outcome)
            if actual is None or actual["positive"] == 0:
                failures.append(f"{outcome}.families.{family}: no matching malicious samples")
                continue
            check(f"{outcome}.families.{family}", actual, family_gates)
    return gates, failures


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _corpus_sha256(corpus_root: Path, samples: list[dict[str, Any]]) -> str:
    """Hash every labeled package member without following symbolic links."""
    hasher = hashlib.sha256()
    package_roots = sorted({(corpus_root / sample["path"]).resolve().parent for sample in samples})
    seen: set[Path] = set()
    for package_root in package_roots:
        for path in sorted(package_root.rglob("*")):
            if path in seen or (path.is_dir() and not path.is_symlink()):
                continue
            seen.add(path)
            relative = path.relative_to(corpus_root).as_posix()
            stat = path.lstat()
            hasher.update(relative.encode("utf-8", errors="surrogateescape"))
            hasher.update(b"\0")
            hasher.update(str(stat.st_mode & 0o7777).encode("ascii"))
            hasher.update(b"\0")
            if path.is_symlink():
                hasher.update(b"SYMLINK\0")
                hasher.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            else:
                hasher.update(path.read_bytes())
            hasher.update(b"\n")
    return hasher.hexdigest()


def evaluate(manifest_path: Path, gates_path: Path | None = None) -> dict[str, Any]:
    """Run a complete, non-executing manifest evaluation."""
    manifest_path = manifest_path.resolve()
    manifest, corpus_root, samples = _resolve_manifest(manifest_path)
    options = _scanner_options(manifest, manifest_path, corpus_root)

    temporary_config_dir = tempfile.TemporaryDirectory(prefix="razin-benchmark-config-")
    trusted_config = options["config_path"]
    if trusted_config is None:
        trusted_config = Path(temporary_config_dir.name) / "razin.yaml"
        trusted_config.write_text("{}\n", encoding="utf-8")
    discovery_config = load_config(corpus_root, trusted_config)
    effective_max_file_mb = options["max_file_mb"] or discovery_config.max_file_mb
    discovered = discover_skill_files(corpus_root, discovery_config.skill_globs, effective_max_file_mb)
    expected_paths = {(corpus_root / sample["path"]).resolve() for sample in samples}
    discovered_paths = set(discovered)
    missing_paths = expected_paths - discovered_paths
    allow_unlisted = manifest.get("allow_unlisted_skills", False)
    if not isinstance(allow_unlisted, bool):
        raise BenchmarkError("manifest.allow_unlisted_skills must be a boolean")
    unlisted = sorted(path.relative_to(corpus_root).as_posix() for path in discovered_paths - expected_paths)
    if unlisted and not allow_unlisted:
        raise BenchmarkError(f"Corpus contains unlisted SKILL.md files: {', '.join(unlisted[:10])}")

    parse_errors: dict[Path, str] = {}
    for path in sorted(expected_paths & discovered_paths):
        try:
            parse_skill_markdown_file(path)
        except Exception as exc:
            parse_errors[path] = str(exc)

    skill_names, _ = assign_unique_skill_names(discovered, corpus_root)
    trusted_config_sha256 = _sha256(trusted_config)
    result = scan_workspace(
        root=corpus_root,
        config_path=trusted_config,
        no_cache=True,
        max_file_mb=options["max_file_mb"],
        profile=options["profile"],
        disable_rules=options["disable_rules"],
        only_rules=options["only_rules"],
    )
    temporary_config_dir.cleanup()

    findings_by_skill: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        findings_by_skill[finding.skill].append(finding)
    package_outcomes = {outcome.skill: outcome for outcome in result.package_outcomes}

    outcomes: list[dict[str, Any]] = []
    expectation_failures: list[str] = []
    for sample in samples:
        path = (corpus_root / sample["path"]).resolve()
        skill = skill_names.get(path)
        findings = findings_by_skill[skill] if skill is not None else []
        evidence_verdict = evidence_verdict_for_package(findings)
        package_outcome = package_outcomes.get(skill) if skill is not None else None
        coverage_status = package_outcome.coverage_status if package_outcome is not None else "incomplete"
        evidence_block_positive = evidence_verdict == "high-confidence-malicious-evidence"
        evidence_review_positive = evidence_verdict in {"high-confidence-malicious-evidence", "review-required"}
        block_positive = evidence_block_positive and coverage_status == "complete"
        review_positive = evidence_review_positive and coverage_status == "complete"
        incomplete_reasons: list[str] = list(package_outcome.coverage_reasons if package_outcome is not None else ())
        if path in missing_paths:
            incomplete_reasons.append("not_discovered")
        if path in parse_errors:
            incomplete_reasons.append(f"parse_error: {parse_errors[path]}")
        if any(finding.rule_id == "INCOMPLETE_SCAN" for finding in findings):
            incomplete_reasons.append("scanner_reported_incomplete")
        if any(finding.rule_id == "DYNAMIC_ANALYSIS_REQUIRED" for finding in findings):
            incomplete_reasons.append("dynamic_analysis_required")
        if coverage_status == "incomplete" and not incomplete_reasons:
            incomplete_reasons.append("scanner_coverage_incomplete")
        if coverage_status == "not-evaluated" and not incomplete_reasons:
            incomplete_reasons.append("coverage-not-evaluated")
        matched = sorted({finding.rule_id for finding in findings})
        missing_expected = sorted(set(sample["expected_rule_ids"]) - set(matched))
        if missing_expected:
            expectation_failures.append(f"{sample['id']}: missing expected rules {', '.join(missing_expected)}")
        for field, actual in (("expected_block", block_positive), ("expected_review", review_positive)):
            expected = sample[field]
            if expected is not None and expected != actual:
                expectation_failures.append(f"{sample['id']}: {field} expected {expected}, observed {actual}")
        outcomes.append(
            {
                "id": sample["id"],
                "path": sample["path"],
                "label": sample["label"],
                "family": sample["family"],
                "diagnostic_group": sample["diagnostic_group"],
                "skill": skill,
                "evidence_verdict": evidence_verdict,
                "coverage_status": coverage_status,
                "coverage_reasons": sorted(set(incomplete_reasons)),
                "evidence_block_positive": evidence_block_positive,
                "evidence_review_positive": evidence_review_positive,
                "block_positive": block_positive,
                "review_positive": review_positive,
                "incomplete": coverage_status == "incomplete",
                "not_evaluated": coverage_status == "not-evaluated",
                "coverage_failed": coverage_status != "complete",
                "incomplete_reasons": sorted(set(incomplete_reasons)),
                "finding_count": len(findings),
                "matched_rule_ids": matched,
                "missing_expected_rule_ids": missing_expected,
            }
        )

    metrics = {outcome: compute_metrics(outcomes, f"{outcome}_positive") for outcome in OUTCOMES}
    benign_controls = [item for item in outcomes if item["label"] == "benign"]
    malicious_by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in outcomes:
        if item["label"] == "malicious":
            malicious_by_family[item["family"]].append(item)
    family_metrics = {
        family: {
            outcome: compute_metrics([*family_samples, *benign_controls], f"{outcome}_positive") for outcome in OUTCOMES
        }
        for family, family_samples in sorted(malicious_by_family.items())
    }
    malicious_by_diagnostic_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in outcomes:
        if item["label"] == "malicious" and item["diagnostic_group"] is not None:
            malicious_by_diagnostic_group[item["diagnostic_group"]].append(item)
    diagnostic_group_metrics = {
        group: {
            outcome: compute_metrics([*group_samples, *benign_controls], f"{outcome}_positive") for outcome in OUTCOMES
        }
        for group, group_samples in sorted(malicious_by_diagnostic_group.items())
    }
    resolved_gates = gates_path.resolve() if gates_path else None
    authoritative_families = manifest.get("authoritative_families", False)
    if not isinstance(authoritative_families, bool):
        raise BenchmarkError("manifest.authoritative_families must be a boolean")
    gates, gate_failures = _evaluate_gates(
        metrics,
        family_metrics,
        resolved_gates,
        authoritative_families=authoritative_families,
    )
    gate_failures.extend(expectation_failures)
    gate_status = "not-evaluated" if resolved_gates is None else ("passed" if not gate_failures else "failed")

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "benchmark": _require_string(manifest.get("name", manifest_path.stem), field="manifest.name"),
        "source": manifest.get("source"),
        "metrics": metrics,
        "diagnostic_family_metrics": family_metrics,
        "diagnostic_filename_group_metrics": diagnostic_group_metrics,
        "gates": gates,
        "gate_status": gate_status,
        "gate_passed": None if resolved_gates is None else not gate_failures,
        "gate_failures": gate_failures,
        "expectation_failures": expectation_failures,
        "provenance": {
            "manifest_sha256": _sha256(manifest_path),
            "gates_sha256": _sha256(resolved_gates) if resolved_gates else None,
            "trusted_config_sha256": trusted_config_sha256,
            "corpus_sha256": _corpus_sha256(corpus_root, samples),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "scanner_version": __version__,
        },
        "scanner": {
            "profile": options["profile"] or discovery_config.profile,
            "max_file_mb": effective_max_file_mb,
            "warnings": list(result.warnings),
            "rules_executed": list(result.rules_executed),
            "rules_disabled": list(result.rules_disabled),
        },
        "samples": outcomes,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Razin against a labeled package corpus")
    parser.add_argument("--manifest", required=True, type=Path, help="Package-level benchmark manifest")
    parser.add_argument("--gates", type=Path, help="Optional quality-gate configuration")
    parser.add_argument("--output", type=Path, help="Write the complete JSON report to this path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        report = evaluate(args.manifest, args.gates)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        for outcome in OUTCOMES:
            metrics = report["metrics"][outcome]
            print(
                f"{outcome}: samples={metrics['samples']} tp={metrics['true_positive']} "
                f"fp={metrics['false_positive']} fn={metrics['false_negative']} "
                f"tn={metrics['true_negative']} precision={metrics['precision']} "
                f"recall={metrics['recall']} f1={metrics['f1']} fpr={metrics['false_positive_rate']}"
            )
        for failure in report["gate_failures"]:
            print(f"gate failure: {failure}", file=sys.stderr)
        return 1 if report["gate_failures"] else 0
    except (BenchmarkError, OSError, ValueError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
