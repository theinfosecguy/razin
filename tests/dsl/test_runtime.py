"""Tests for DSL runtime engine: loading, filtering, fingerprinting, parity, scan integration."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from razin.config import RazinConfig, effective_detector_ids, load_config
from razin.detectors import build_detectors
from razin.dsl import DslEngine
from razin.dsl.runtime import RULES_DIR
from razin.exceptions import ConfigError
from razin.exceptions.dsl import DslRuntimeError
from razin.model import FindingCandidate, ParsedSkillDocument
from razin.parsers import parse_skill_markdown_file
from razin.scanner.discovery import derive_skill_name

from .conftest import _skill_file, _write_rule_file


def test_load_all_bundled_rules() -> None:
    """Engine loads all 19 bundled rules."""
    engine = DslEngine()
    assert engine.rule_count == 19
    assert "AUTH_CONNECTION" in engine.rule_ids
    assert "NET_RAW_IP" in engine.rule_ids
    assert "PROMPT_INJECTION" in engine.rule_ids
    assert "HIDDEN_INSTRUCTION" in engine.rule_ids


def test_filter_rule_ids() -> None:
    """Engine filters to requested rule IDs."""
    engine = DslEngine(rule_ids=frozenset({"AUTH_CONNECTION", "NET_RAW_IP"}))
    assert engine.rule_count == 2
    assert set(engine.rule_ids) == {"AUTH_CONNECTION", "NET_RAW_IP"}


def test_filter_rule_ids_by_public_rule_id() -> None:
    """Public rule ID maps to multiple internal rules."""
    engine = DslEngine(rule_ids=frozenset({"SECRET_REF"}))
    assert set(engine.rule_ids) == {"SECRET_REF", "SECRET_REF_KEYS"}


def test_empty_filter_loads_nothing() -> None:
    """Empty rule filter produces zero rules."""
    engine = DslEngine(rule_ids=frozenset())
    assert engine.rule_count == 0


def test_fingerprint_is_stable() -> None:
    """Fingerprint is deterministic across identical engines."""
    e1 = DslEngine()
    e2 = DslEngine()
    assert e1.fingerprint() == e2.fingerprint()


def test_fingerprint_changes_with_rule_filter() -> None:
    """Rule filter changes the fingerprint."""
    full = DslEngine()
    partial = DslEngine(rule_ids=frozenset({"AUTH_CONNECTION"}))
    assert full.fingerprint() != partial.fingerprint()


def test_rules_dir_mode_loads_only_custom_directory(tmp_path: Path) -> None:
    """Custom rules_dir loads only custom rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom_a.yaml", rule_id="CUSTOM_A")
    _write_rule_file(rules_dir / "custom_b.yaml", rule_id="CUSTOM_B")

    engine = DslEngine(rules_dir=rules_dir)

    assert engine.rule_count == 2
    assert set(engine.rule_ids) == {"CUSTOM_A", "CUSTOM_B"}


def test_rule_files_mode_loads_selected_files(tmp_path: Path) -> None:
    """Selected rule_files loads only those specific files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_a = _write_rule_file(rules_dir / "a.yaml", rule_id="CUSTOM_A")
    custom_b = _write_rule_file(rules_dir / "b.yaml", rule_id="CUSTOM_B")

    engine = DslEngine(rule_files=(custom_b, custom_a))

    assert engine.rule_count == 2
    assert set(engine.rule_ids) == {"CUSTOM_A", "CUSTOM_B"}


def test_rule_files_mode_requires_yaml_extension(tmp_path: Path) -> None:
    """Rule files must have .yaml extension."""
    bad = tmp_path / "rule.yml"
    bad.write_text("rule_id: CUSTOM\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="\\.yaml"):
        DslEngine(rule_files=(bad,))


def test_rule_files_mode_rejects_missing_path(tmp_path: Path) -> None:
    """Missing rule file path is rejected."""
    with pytest.raises(ConfigError, match="does not exist"):
        DslEngine(rule_files=(tmp_path / "missing.yaml",))


def test_rule_source_modes_are_mutually_exclusive(tmp_path: Path) -> None:
    """Specifying both rules_dir and rule_files raises."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom = _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM")

    with pytest.raises(ConfigError, match="either rules_dir or rule_files"):
        DslEngine(rules_dir=rules_dir, rule_files=(custom,))


def test_duplicate_rule_id_fails_fast(tmp_path: Path) -> None:
    """Duplicate rule IDs produce an error."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "a.yaml", rule_id="DUPLICATE")
    _write_rule_file(rules_dir / "b.yaml", rule_id="DUPLICATE")

    with pytest.raises(ConfigError, match="Duplicate rule_id"):
        DslEngine(rules_dir=rules_dir)


def test_invalid_yaml_fails_fast(tmp_path: Path) -> None:
    """Invalid YAML in a rule file produces an error."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yaml").write_text("rule_id: [", encoding="utf-8")

    with pytest.raises(ConfigError, match="Invalid YAML"):
        DslEngine(rules_dir=rules_dir)


def test_fingerprint_changes_when_rule_file_selection_changes(tmp_path: Path) -> None:
    """Different rule file selections produce different fingerprints."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_a = _write_rule_file(rules_dir / "a.yaml", rule_id="CUSTOM_A")
    custom_b = _write_rule_file(rules_dir / "b.yaml", rule_id="CUSTOM_B")

    only_a = DslEngine(rule_files=(custom_a,))
    only_b = DslEngine(rule_files=(custom_b,))

    assert only_a.fingerprint() != only_b.fingerprint()


def test_fingerprint_is_deterministic_for_rule_file_order(tmp_path: Path) -> None:
    """Rule file order does not affect fingerprint."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_a = _write_rule_file(rules_dir / "a.yaml", rule_id="CUSTOM_A")
    custom_b = _write_rule_file(rules_dir / "b.yaml", rule_id="CUSTOM_B")

    first = DslEngine(rule_files=(custom_b, custom_a))
    second = DslEngine(rule_files=(custom_a, custom_b))

    assert first.fingerprint() == second.fingerprint()


def test_run_rule_raises_for_unknown_id(tmp_path: Path) -> None:
    """Running an unknown rule ID raises DslRuntimeError."""
    engine = DslEngine()
    parsed = parse_skill_markdown_file(_skill_file(tmp_path, "---\nname: test\n---\n# Hello\n"))
    config = RazinConfig()
    with pytest.raises(DslRuntimeError, match="not loaded"):
        engine.run_rule("NONEXISTENT_RULE", skill_name="test", parsed=parsed, config=config)


def test_rules_dir_not_found_fails_fast(tmp_path: Path) -> None:
    """Non-existent rules_dir raises ConfigError."""
    with pytest.raises(ConfigError, match="Rules directory does not exist"):
        DslEngine(rules_dir=tmp_path / "nonexistent")


def test_benign_skill_produces_no_findings(basic_repo_root: Path) -> None:
    """Benign skill fixture produces zero findings."""
    engine = DslEngine()
    benign = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(benign)
    config = load_config(basic_repo_root)
    findings = engine.run_all(skill_name="benign_skill", parsed=parsed, config=config)
    assert len(findings) == 0


def test_risky_skill_produces_findings(basic_repo_root: Path) -> None:
    """Risky skill fixture produces at least one finding."""
    engine = DslEngine()
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky)
    config = load_config(basic_repo_root)
    findings = engine.run_all(skill_name="risky_skill", parsed=parsed, config=config)
    assert len(findings) > 0


@pytest.fixture()
def _risky_results(basic_repo_root: Path) -> tuple[list[FindingCandidate], list[FindingCandidate]]:
    """Run Python detectors and DSL engine on risky skill, return both result sets."""
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky)
    config = load_config(basic_repo_root)
    skill_name = derive_skill_name(risky, basic_repo_root)

    py_detectors = build_detectors(effective_detector_ids(config))
    py_findings: list[FindingCandidate] = []
    for d in py_detectors:
        py_findings.extend(d.run(skill_name=skill_name, parsed=parsed, config=config))

    dsl_engine = DslEngine()
    dsl_findings = dsl_engine.run_all(skill_name=skill_name, parsed=parsed, config=config)
    return py_findings, dsl_findings


def test_same_finding_count(_risky_results: tuple[list[FindingCandidate], list[FindingCandidate]]) -> None:
    """Python and DSL produce the same number of findings."""
    py, dsl = _risky_results
    assert len(py) == len(dsl)


def test_same_rule_ids_multiset(
    _risky_results: tuple[list[FindingCandidate], list[FindingCandidate]],
) -> None:
    """Python and DSL produce the same rule ID multiset."""
    py, dsl = _risky_results
    py_ids = sorted(f.rule_id for f in py)
    dsl_ids = sorted(f.rule_id for f in dsl)
    assert py_ids == dsl_ids


def test_same_scores(_risky_results: tuple[list[FindingCandidate], list[FindingCandidate]]) -> None:
    """Python and DSL produce the same scores per rule."""
    py, dsl = _risky_results
    py_scores = sorted((f.rule_id, f.score) for f in py)
    dsl_scores = sorted((f.rule_id, f.score) for f in dsl)
    assert py_scores == dsl_scores


def test_same_confidences(_risky_results: tuple[list[FindingCandidate], list[FindingCandidate]]) -> None:
    """Python and DSL produce the same confidences per rule."""
    py, dsl = _risky_results
    py_conf = sorted((f.rule_id, f.confidence) for f in py)
    dsl_conf = sorted((f.rule_id, f.confidence) for f in dsl)
    assert py_conf == dsl_conf


def test_secret_ref_finding_keeps_internal_provenance(
    _risky_results: tuple[list[FindingCandidate], list[FindingCandidate]],
) -> None:
    """SECRET_REF findings preserve internal rule ID provenance."""
    _, dsl = _risky_results
    secret_findings = [finding for finding in dsl if finding.rule_id == "SECRET_REF"]
    internal_ids = {finding.internal_rule_id for finding in secret_findings}
    assert "SECRET_REF_KEYS" in internal_ids
    assert "SECRET_REF" in internal_ids


PYTHON_DSL_MAP: dict[str, list[str]] = {
    "NET_RAW_IP": ["NET_RAW_IP"],
    "NET_UNKNOWN_DOMAIN": ["NET_UNKNOWN_DOMAIN"],
    "SECRET_REF": ["SECRET_REF"],
    "EXEC_FIELDS": ["EXEC_FIELDS"],
    "OPAQUE_BLOB": ["OPAQUE_BLOB"],
    "TYPOSQUAT": ["TYPOSQUAT"],
    "BUNDLED_SCRIPTS": ["BUNDLED_SCRIPTS"],
    "MCP_REQUIRED": ["MCP_REQUIRED"],
    "MCP_ENDPOINT": ["MCP_ENDPOINT"],
    "MCP_DENYLIST": ["MCP_DENYLIST"],
    "TOOL_INVOCATION": ["TOOL_INVOCATION"],
    "DYNAMIC_SCHEMA": ["DYNAMIC_SCHEMA"],
    "AUTH_CONNECTION": ["AUTH_CONNECTION"],
    "EXTERNAL_URLS": ["EXTERNAL_URLS"],
    "NET_DOC_DOMAIN": ["NET_DOC_DOMAIN"],
    "PROMPT_INJECTION": ["PROMPT_INJECTION"],
    "HIDDEN_INSTRUCTION": ["HIDDEN_INSTRUCTION"],
}


def _run_python_detector(
    py_id: str, skill_name: str, parsed: ParsedSkillDocument, config: RazinConfig
) -> list[FindingCandidate]:
    """Run a single Python detector by ID and return its results."""
    detectors = build_detectors((py_id,))
    results: list[FindingCandidate] = []
    for d in detectors:
        results.extend(d.run(skill_name=skill_name, parsed=parsed, config=config))
    return results


def _run_dsl_rules(
    dsl_ids: list[str],
    skill_name: str,
    parsed: ParsedSkillDocument,
    config: RazinConfig,
) -> list[FindingCandidate]:
    """Run selected DSL rules and return their results."""
    engine = DslEngine(rule_ids=frozenset(dsl_ids))
    return engine.run_all(skill_name=skill_name, parsed=parsed, config=config)


@pytest.mark.parametrize("py_id", list(PYTHON_DSL_MAP.keys()))
def test_detector_score_parity(py_id: str, basic_repo_root: Path) -> None:
    """Per-detector score parity between Python and DSL."""
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky)
    config = load_config(basic_repo_root)
    skill_name = derive_skill_name(risky, basic_repo_root)

    py_findings = _run_python_detector(py_id, skill_name, parsed, config)
    dsl_ids = PYTHON_DSL_MAP[py_id]
    dsl_findings = _run_dsl_rules(dsl_ids, skill_name, parsed, config)

    assert len(py_findings) == len(
        dsl_findings
    ), f"{py_id}: python={len(py_findings)} findings, dsl={len(dsl_findings)} findings"

    py_scores = sorted(f.score for f in py_findings)
    dsl_scores = sorted(f.score for f in dsl_findings)
    assert py_scores == dsl_scores, f"{py_id}: score mismatch python={py_scores} dsl={dsl_scores}"


def test_dsl_scan_produces_results(basic_repo_root: Path, tmp_path: Path) -> None:
    """scan_workspace with DSL engine produces results."""
    from razin.scanner import scan_workspace

    result = scan_workspace(
        root=basic_repo_root,
        out=tmp_path / "out",
        engine="dsl",
    )
    assert result.total_findings > 0
    assert result.scanned_files >= 2


def test_dsl_scan_benign_only(tmp_path: Path) -> None:
    """Benign-only workspace scan produces zero findings."""
    from razin.scanner import scan_workspace

    skill_dir = tmp_path / "skills" / "safe"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: safe-skill\n---\n# Safe\nA benign skill.\n",
        encoding="utf-8",
    )
    result = scan_workspace(root=tmp_path, engine="dsl")
    assert result.total_findings == 0
    assert result.scanned_files == 1


@pytest.mark.parametrize("engine", ["legacy", "optionc", "default"])
def test_removed_engines_raise_config_error(basic_repo_root: Path, tmp_path: Path, engine: str) -> None:
    """Legacy, optionc, and default engine names are rejected."""
    from razin.scanner import scan_workspace

    with pytest.raises(ConfigError, match="supports only 'dsl'"):
        scan_workspace(
            root=basic_repo_root,
            out=tmp_path / "out",
            engine=engine,
        )


def test_scan_with_custom_rules_dir_uses_custom_rules_only(tmp_path: Path) -> None:
    """Custom rules_dir in scan loads only custom rules."""
    from razin.scanner import scan_workspace

    skill_dir = tmp_path / "skills" / "custom"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: custom\n---\n# Custom\ncommand: run\n",
        encoding="utf-8",
    )

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(
        rules_dir / "custom.yaml",
        rule_id="CUSTOM_RULE",
        match={"source": "keys", "strategy": "key_pattern_match", "keywords": ["command"], "match_mode": "exact"},
    )

    result = scan_workspace(root=tmp_path, out=tmp_path / "out", rules_dir=rules_dir)
    assert result.total_findings == 1
    assert {finding.rule_id for finding in result.findings} == {"CUSTOM_RULE"}


def test_scan_with_rule_files_uses_selected_subset(tmp_path: Path) -> None:
    """scan_workspace with rule_files loads only the selected subset."""
    from razin.scanner import scan_workspace

    skill_dir = tmp_path / "skills" / "subset"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: subset\n---\n# Subset\ncommand: run\nscript: execute\n",
        encoding="utf-8",
    )

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    command_rule = _write_rule_file(
        rules_dir / "command.yaml",
        rule_id="COMMAND_RULE",
        match={
            "source": "keys",
            "strategy": "key_pattern_match",
            "keywords": ["command"],
            "match_mode": "exact",
        },
    )
    _write_rule_file(
        rules_dir / "script.yaml",
        rule_id="SCRIPT_RULE",
        match={
            "source": "keys",
            "strategy": "key_pattern_match",
            "keywords": ["script"],
            "match_mode": "exact",
        },
    )

    result = scan_workspace(
        root=tmp_path,
        out=tmp_path / "out",
        rule_files=(command_rule,),
    )
    assert result.total_findings == 1
    assert {finding.rule_id for finding in result.findings} == {"COMMAND_RULE"}


def test_scan_rejects_conflicting_rule_source_arguments(tmp_path: Path) -> None:
    """Conflicting --rules-dir and --rule-file arguments raise."""
    from razin.scanner import scan_workspace

    skill_dir = tmp_path / "skills" / "conflict"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: conflict\n---\n# Conflict\n", encoding="utf-8")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_RULE")

    with pytest.raises(ConfigError, match="either --rules-dir or --rule-file"):
        scan_workspace(
            root=tmp_path,
            rules_dir=rules_dir,
            rule_files=(rule_file,),
        )


def test_removed_engine_rejected_without_breaking_dsl_cache(basic_repo_root: Path, tmp_path: Path) -> None:
    """Rejected engine does not corrupt the DSL cache."""
    from razin.scanner import scan_workspace

    out = tmp_path / "out"
    first = scan_workspace(root=basic_repo_root, out=out, engine="dsl")
    with pytest.raises(ConfigError, match="supports only 'dsl'"):
        scan_workspace(root=basic_repo_root, out=out, engine="legacy")
    second = scan_workspace(root=basic_repo_root, out=out, engine="dsl")

    assert first.cache_misses >= 1
    assert second.cache_hits >= 1


def test_unchanged_engine_and_rulepack_hits_cache(basic_repo_root: Path, tmp_path: Path) -> None:
    """Unchanged engine and rulepack produce cache hit on rescan."""
    from razin.scanner import scan_workspace

    out = tmp_path / "out"
    first = scan_workspace(root=basic_repo_root, out=out, engine="dsl")
    second = scan_workspace(root=basic_repo_root, out=out, engine="dsl")

    assert first.cache_misses >= 1
    assert second.cache_hits >= 1


def test_custom_rule_source_forces_cache_miss(basic_repo_root: Path, tmp_path: Path) -> None:
    """Custom rule source forces a cache miss."""
    from razin.scanner import scan_workspace

    custom_rules = tmp_path / "rules"
    shutil.copytree(RULES_DIR, custom_rules)

    out = tmp_path / "out"
    first = scan_workspace(root=basic_repo_root, out=out, engine="dsl")
    second = scan_workspace(root=basic_repo_root, out=out, engine="dsl", rules_dir=custom_rules)
    third = scan_workspace(root=basic_repo_root, out=out, engine="dsl", rules_dir=custom_rules)

    assert first.cache_misses >= 1
    assert second.cache_hits == 0
    assert second.cache_misses >= 1
    assert third.cache_hits >= 1


def test_rulepack_change_forces_cache_miss(basic_repo_root: Path, tmp_path: Path) -> None:
    """Rule content change forces a cache miss."""
    from razin.scanner import scan_workspace

    custom_rules = tmp_path / "rules"
    shutil.copytree(RULES_DIR, custom_rules)

    out = tmp_path / "out"
    first = scan_workspace(root=basic_repo_root, out=out, engine="dsl", rules_dir=custom_rules)

    exec_rule = custom_rules / "exec_fields.yaml"
    original_text = exec_rule.read_text(encoding="utf-8")
    assert "base_score: 72" in original_text
    updated = original_text.replace("base_score: 72", "base_score: 73", 1)
    exec_rule.write_text(updated, encoding="utf-8")

    second = scan_workspace(root=basic_repo_root, out=out, engine="dsl", rules_dir=custom_rules)
    assert first.cache_misses >= 1
    assert second.cache_hits == 0
    assert second.cache_misses >= 1


def test_profile_override_changes_score(tmp_path: Path) -> None:
    """Profile overlay changes the effective score."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "custom.yaml").write_text(
        "rule_id: CUSTOM_RULE\n"
        "version: 1\n"
        "metadata:\n"
        "  title: Custom test\n"
        "  description: Test rule\n"
        "  recommendation: Fix\n"
        "  confidence: medium\n"
        "scoring:\n"
        "  base_score: 50\n"
        "profiles:\n"
        "  strict:\n"
        "    score_override: 90\n"
        "  audit:\n"
        "    score_override: 0\n"
        "match:\n"
        "  source: keys\n"
        "  strategy: key_pattern_match\n"
        "  keywords:\n"
        "    - command\n"
        "  match_mode: exact\n",
        encoding="utf-8",
    )

    skill = _skill_file(tmp_path, "---\nname: test\n---\n# Test\ncommand: run\n")
    parsed = parse_skill_markdown_file(skill)

    engine = DslEngine(rules_dir=rules_dir)
    assert engine.rule_count == 1

    balanced_config = RazinConfig(profile="balanced")
    balanced_findings = engine.run_all(skill_name="test", parsed=parsed, config=balanced_config)
    assert len(balanced_findings) == 1
    assert balanced_findings[0].score == 50

    strict_config = RazinConfig(profile="strict")
    strict_findings = engine.run_all(skill_name="test", parsed=parsed, config=strict_config)
    assert len(strict_findings) == 1
    assert strict_findings[0].score == 90

    audit_config = RazinConfig(profile="audit")
    audit_findings = engine.run_all(skill_name="test", parsed=parsed, config=audit_config)
    assert len(audit_findings) == 1
    assert audit_findings[0].score == 0


def test_replace_mode_uses_only_custom_rules(tmp_path: Path) -> None:
    """Replace mode loads only custom rules, excluding bundled."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_ONLY")

    engine = DslEngine(rules_dir=rules_dir, rules_mode="replace")

    assert engine.rule_count == 1
    assert engine.rule_ids == ["CUSTOM_ONLY"]


def test_overlay_mode_merges_bundled_and_custom(tmp_path: Path) -> None:
    """Overlay mode loads bundled plus custom rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_EXTRA")

    engine = DslEngine(rules_dir=rules_dir, rules_mode="overlay")

    assert "CUSTOM_EXTRA" in engine.rule_ids
    assert "AUTH_CONNECTION" in engine.rule_ids
    assert engine.rule_count > 1


def test_overlay_mode_with_rule_files(tmp_path: Path) -> None:
    """Overlay mode works with rule_files too."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_file = _write_rule_file(rules_dir / "extra.yaml", rule_id="EXTRA_RULE")

    engine = DslEngine(rule_files=(custom_file,), rules_mode="overlay")

    assert "EXTRA_RULE" in engine.rule_ids
    assert "AUTH_CONNECTION" in engine.rule_ids


def test_overlay_duplicate_error_policy_raises(tmp_path: Path) -> None:
    """Overlay with error policy raises on duplicate rule_id."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "auth.yaml", rule_id="AUTH_CONNECTION")

    with pytest.raises(ConfigError, match="Duplicate rule_id 'AUTH_CONNECTION'"):
        DslEngine(rules_dir=rules_dir, rules_mode="overlay", duplicate_policy="error")


def test_overlay_duplicate_override_policy_custom_wins(tmp_path: Path) -> None:
    """Override policy lets custom rule replace bundled with same rule_id."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(
        rules_dir / "auth.yaml",
        rule_id="AUTH_CONNECTION",
        scoring={"base_score": 99},
        match={
            "source": "raw_text",
            "strategy": "hint_count",
            "strong_hints": ["oauth", "login"],
            "weak_hints": ["token", "api key"],
            "min_matches": 2,
        },
    )

    engine = DslEngine(rules_dir=rules_dir, rules_mode="overlay", duplicate_policy="override")

    auth_rules = [r for r in engine._compiled if r.rule_id == "AUTH_CONNECTION"]
    assert len(auth_rules) == 1
    assert auth_rules[0].base_score == 99
    assert str(rules_dir) in auth_rules[0].source_path


def test_overlay_no_custom_source_uses_bundled_only() -> None:
    """Overlay without custom source loads bundled rules only."""
    engine = DslEngine(rules_mode="overlay")

    assert engine.rule_count == 19
    assert "AUTH_CONNECTION" in engine.rule_ids


def test_replace_mode_without_custom_uses_bundled() -> None:
    """Replace mode with no custom source falls back to bundled."""
    engine = DslEngine(rules_mode="replace")

    assert engine.rule_count == 19


def test_overlay_fingerprint_differs_from_replace(tmp_path: Path) -> None:
    """Different rules_mode produces different fingerprints."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_FP")

    replace_engine = DslEngine(rules_dir=rules_dir, rules_mode="replace")
    overlay_engine = DslEngine(rules_dir=rules_dir, rules_mode="overlay")

    assert replace_engine.fingerprint() != overlay_engine.fingerprint()


def test_overlay_override_fingerprint_differs_from_bundled(tmp_path: Path) -> None:
    """Override changes effective rules so fingerprint differs from bundled."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "auth.yaml", rule_id="AUTH_CONNECTION", scoring={"base_score": 99})

    override_engine = DslEngine(rules_dir=rules_dir, rules_mode="overlay", duplicate_policy="override")
    bundled_engine = DslEngine()
    assert override_engine.fingerprint() != bundled_engine.fingerprint()


def test_overlay_cache_miss_when_mode_changes(tmp_path: Path) -> None:
    """Switching rules_mode forces a cache miss."""
    from razin.scanner import scan_workspace

    skill_dir = tmp_path / "skills" / "test"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: test\n---\n# Test\ncommand: run\n",
        encoding="utf-8",
    )

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_CACHE")

    out = tmp_path / "out"
    first = scan_workspace(root=tmp_path, out=out, rules_dir=rules_dir, rules_mode="replace")
    second = scan_workspace(root=tmp_path, out=out, rules_dir=rules_dir, rules_mode="overlay")

    assert first.cache_misses >= 1
    assert second.cache_misses >= 1


def test_overlay_override_rejects_custom_vs_custom_duplicate(tmp_path: Path) -> None:
    """Override only applies to bundled-vs-custom; custom-vs-custom always errors."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "a.yaml", rule_id="SAME_ID")
    _write_rule_file(rules_dir / "b.yaml", rule_id="SAME_ID", scoring={"base_score": 99})

    with pytest.raises(ConfigError, match="Duplicate rule_id 'SAME_ID'"):
        DslEngine(rules_dir=rules_dir, rules_mode="overlay", duplicate_policy="override")
