"""Tests for DSL v1 engine: schema, compiler, runtime, parity with Python detectors."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from razin.config import RazinConfig, effective_detector_ids, load_config
from razin.detectors import build_detectors
from razin.dsl import DslEngine
from razin.dsl.compiler import CompiledRule, compile_rule
from razin.dsl.errors import DslRuntimeError, DslSchemaError
from razin.dsl.runtime import RULES_DIR
from razin.dsl.schema import validate_rule
from razin.exceptions import ConfigError
from razin.model import FindingCandidate, ParsedSkillDocument
from razin.parsers import parse_skill_markdown_file
from razin.scanner.discovery import derive_skill_name


def _skill_file(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "SKILL.md"
    f.write_text(content, encoding="utf-8")
    return f


def _minimal_rule(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rule_id": "TEST_RULE",
        "version": 1,
        "metadata": {
            "title": "Test rule",
            "description": "Test description",
            "recommendation": "Fix it",
            "confidence": "medium",
        },
        "scoring": {"base_score": 50},
        "match": {
            "source": "fields",
            "strategy": "key_pattern_match",
            "keywords": ["test"],
        },
        "dedupe": True,
    }
    base.update(overrides)
    return base


def _write_rule_file(path: Path, **overrides: Any) -> Path:
    payload = _minimal_rule(**overrides)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_valid_minimal_rule() -> None:
    validate_rule(_minimal_rule(), "<test>")


def test_rejects_unknown_top_key() -> None:
    with pytest.raises(DslSchemaError, match="unknown top-level keys"):
        validate_rule(_minimal_rule(bogus="bad"), "<test>")


def test_rejects_missing_rule_id() -> None:
    rule = _minimal_rule()
    del rule["rule_id"]
    with pytest.raises(DslSchemaError, match="missing required key 'rule_id'"):
        validate_rule(rule, "<test>")


def test_rejects_wrong_version() -> None:
    with pytest.raises(DslSchemaError, match="version"):
        validate_rule(_minimal_rule(version=2), "<test>")


def test_rejects_unknown_strategy() -> None:
    rule = _minimal_rule()
    rule["match"]["strategy"] = "hacks"
    with pytest.raises(DslSchemaError, match="match.strategy"):
        validate_rule(rule, "<test>")


def test_rejects_invalid_confidence() -> None:
    rule = _minimal_rule()
    rule["metadata"]["confidence"] = "very_high"
    with pytest.raises(DslSchemaError, match="confidence"):
        validate_rule(rule, "<test>")


def test_rejects_out_of_range_score() -> None:
    rule = _minimal_rule()
    rule["scoring"]["base_score"] = 150
    with pytest.raises(DslSchemaError, match="base_score"):
        validate_rule(rule, "<test>")


def test_rejects_invalid_source() -> None:
    rule = _minimal_rule()
    rule["match"]["source"] = "network"
    with pytest.raises(DslSchemaError, match="match.source"):
        validate_rule(rule, "<test>")


def test_rejects_non_bool_dedupe() -> None:
    with pytest.raises(DslSchemaError, match="dedupe"):
        validate_rule(_minimal_rule(dedupe="yes"), "<test>")


def test_compile_minimal_rule() -> None:
    compiled = compile_rule(_minimal_rule(), "<test>")
    assert isinstance(compiled, CompiledRule)
    assert compiled.source_path == "<test>"
    assert compiled.rule_id == "TEST_RULE"
    assert compiled.public_rule_id == "TEST_RULE"
    assert compiled.version == 1
    assert compiled.strategy_name == "key_pattern_match"
    assert compiled.base_score == 50
    assert compiled.dedupe is True


def test_compile_respects_public_rule_id() -> None:
    compiled = compile_rule(_minimal_rule(public_rule_id="PUBLIC_RULE"), "<test>")
    assert compiled.rule_id == "TEST_RULE"
    assert compiled.public_rule_id == "PUBLIC_RULE"


def test_compile_rejects_unregistered_strategy() -> None:
    rule = _minimal_rule()
    rule["match"]["strategy"] = "hacks"
    with pytest.raises(DslSchemaError):
        compile_rule(rule, "<test>")


def test_load_all_bundled_rules() -> None:
    engine = DslEngine()
    assert engine.rule_count == 15
    assert "AUTH_CONNECTION" in engine.rule_ids
    assert "NET_RAW_IP" in engine.rule_ids


def test_filter_rule_ids() -> None:
    engine = DslEngine(rule_ids=frozenset({"AUTH_CONNECTION", "NET_RAW_IP"}))
    assert engine.rule_count == 2
    assert set(engine.rule_ids) == {"AUTH_CONNECTION", "NET_RAW_IP"}


def test_filter_rule_ids_by_public_rule_id() -> None:
    engine = DslEngine(rule_ids=frozenset({"SECRET_REF"}))
    assert set(engine.rule_ids) == {"SECRET_REF", "SECRET_REF_KEYS"}


def test_empty_filter_loads_nothing() -> None:
    engine = DslEngine(rule_ids=frozenset())
    assert engine.rule_count == 0


def test_fingerprint_is_stable() -> None:
    e1 = DslEngine()
    e2 = DslEngine()
    assert e1.fingerprint() == e2.fingerprint()


def test_fingerprint_changes_with_rule_filter() -> None:
    full = DslEngine()
    partial = DslEngine(rule_ids=frozenset({"AUTH_CONNECTION"}))
    assert full.fingerprint() != partial.fingerprint()


def test_rules_dir_mode_loads_only_custom_directory(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom_a.yaml", rule_id="CUSTOM_A")
    _write_rule_file(rules_dir / "custom_b.yaml", rule_id="CUSTOM_B")

    engine = DslEngine(rules_dir=rules_dir)

    assert engine.rule_count == 2
    assert set(engine.rule_ids) == {"CUSTOM_A", "CUSTOM_B"}


def test_rule_files_mode_loads_selected_files(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_a = _write_rule_file(rules_dir / "a.yaml", rule_id="CUSTOM_A")
    custom_b = _write_rule_file(rules_dir / "b.yaml", rule_id="CUSTOM_B")

    engine = DslEngine(rule_files=(custom_b, custom_a))

    assert engine.rule_count == 2
    assert set(engine.rule_ids) == {"CUSTOM_A", "CUSTOM_B"}


def test_rule_files_mode_requires_yaml_extension(tmp_path: Path) -> None:
    bad = tmp_path / "rule.yml"
    bad.write_text("rule_id: CUSTOM\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="\\.yaml"):
        DslEngine(rule_files=(bad,))


def test_rule_files_mode_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        DslEngine(rule_files=(tmp_path / "missing.yaml",))


def test_rule_source_modes_are_mutually_exclusive(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom = _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM")

    with pytest.raises(ConfigError, match="either rules_dir or rule_files"):
        DslEngine(rules_dir=rules_dir, rule_files=(custom,))


def test_duplicate_rule_id_fails_fast(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "a.yaml", rule_id="DUPLICATE")
    _write_rule_file(rules_dir / "b.yaml", rule_id="DUPLICATE")

    with pytest.raises(ConfigError, match="Duplicate rule_id"):
        DslEngine(rules_dir=rules_dir)


def test_invalid_yaml_fails_fast(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yaml").write_text("rule_id: [", encoding="utf-8")

    with pytest.raises(ConfigError, match="Invalid YAML"):
        DslEngine(rules_dir=rules_dir)


def test_fingerprint_changes_when_rule_file_selection_changes(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_a = _write_rule_file(rules_dir / "a.yaml", rule_id="CUSTOM_A")
    custom_b = _write_rule_file(rules_dir / "b.yaml", rule_id="CUSTOM_B")

    only_a = DslEngine(rule_files=(custom_a,))
    only_b = DslEngine(rule_files=(custom_b,))

    assert only_a.fingerprint() != only_b.fingerprint()


def test_fingerprint_is_deterministic_for_rule_file_order(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_a = _write_rule_file(rules_dir / "a.yaml", rule_id="CUSTOM_A")
    custom_b = _write_rule_file(rules_dir / "b.yaml", rule_id="CUSTOM_B")

    first = DslEngine(rule_files=(custom_b, custom_a))
    second = DslEngine(rule_files=(custom_a, custom_b))

    assert first.fingerprint() == second.fingerprint()


def test_run_rule_raises_for_unknown_id(tmp_path: Path) -> None:
    engine = DslEngine()
    parsed = parse_skill_markdown_file(_skill_file(tmp_path, "---\nname: test\n---\n# Hello\n"))
    config = RazinConfig()
    with pytest.raises(DslRuntimeError, match="not loaded"):
        engine.run_rule("NONEXISTENT_RULE", skill_name="test", parsed=parsed, config=config)


def test_benign_skill_produces_no_findings(basic_repo_root: Path) -> None:
    engine = DslEngine()
    benign = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(benign)
    config = load_config(basic_repo_root)
    findings = engine.run_all(skill_name="benign_skill", parsed=parsed, config=config)
    assert len(findings) == 0


def test_risky_skill_produces_findings(basic_repo_root: Path) -> None:
    engine = DslEngine()
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky)
    config = load_config(basic_repo_root)
    findings = engine.run_all(skill_name="risky_skill", parsed=parsed, config=config)
    assert len(findings) > 0


@pytest.fixture()
def _risky_results(basic_repo_root: Path) -> tuple[list[FindingCandidate], list[FindingCandidate]]:
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
    py, dsl = _risky_results
    assert len(py) == len(dsl)


def test_same_rule_ids_multiset(
    _risky_results: tuple[list[FindingCandidate], list[FindingCandidate]],
) -> None:
    py, dsl = _risky_results
    py_ids = sorted(f.rule_id for f in py)
    dsl_ids = sorted(f.rule_id for f in dsl)
    assert py_ids == dsl_ids


def test_same_scores(_risky_results: tuple[list[FindingCandidate], list[FindingCandidate]]) -> None:
    py, dsl = _risky_results
    py_scores = sorted((f.rule_id, f.score) for f in py)
    dsl_scores = sorted((f.rule_id, f.score) for f in dsl)
    assert py_scores == dsl_scores


def test_same_confidences(_risky_results: tuple[list[FindingCandidate], list[FindingCandidate]]) -> None:
    py, dsl = _risky_results
    py_conf = sorted((f.rule_id, f.confidence) for f in py)
    dsl_conf = sorted((f.rule_id, f.confidence) for f in dsl)
    assert py_conf == dsl_conf


def test_secret_ref_finding_keeps_internal_provenance(
    _risky_results: tuple[list[FindingCandidate], list[FindingCandidate]],
) -> None:
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
}


def _run_python_detector(
    py_id: str, skill_name: str, parsed: ParsedSkillDocument, config: RazinConfig
) -> list[FindingCandidate]:
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
    engine = DslEngine(rule_ids=frozenset(dsl_ids))
    return engine.run_all(skill_name=skill_name, parsed=parsed, config=config)


@pytest.mark.parametrize("py_id", list(PYTHON_DSL_MAP.keys()))
def test_detector_score_parity(py_id: str, basic_repo_root: Path) -> None:
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
    from razin.scanner import scan_workspace

    result = scan_workspace(
        root=basic_repo_root,
        out=tmp_path / "out",
        engine="dsl",
    )
    assert result.total_findings > 0
    assert result.scanned_files >= 2


def test_dsl_scan_benign_only(tmp_path: Path) -> None:
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
    from razin.exceptions import ConfigError
    from razin.scanner import scan_workspace

    with pytest.raises(ConfigError, match="supports only 'dsl'"):
        scan_workspace(
            root=basic_repo_root,
            out=tmp_path / "out",
            engine=engine,
        )


def test_scan_with_custom_rules_dir_uses_custom_rules_only(tmp_path: Path) -> None:
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
    from razin.exceptions import ConfigError
    from razin.scanner import scan_workspace

    out = tmp_path / "out"
    first = scan_workspace(root=basic_repo_root, out=out, engine="dsl")
    with pytest.raises(ConfigError, match="supports only 'dsl'"):
        scan_workspace(root=basic_repo_root, out=out, engine="legacy")
    second = scan_workspace(root=basic_repo_root, out=out, engine="dsl")

    assert first.cache_misses >= 1
    assert second.cache_hits >= 1


def test_unchanged_engine_and_rulepack_hits_cache(basic_repo_root: Path, tmp_path: Path) -> None:
    from razin.scanner import scan_workspace

    out = tmp_path / "out"
    first = scan_workspace(root=basic_repo_root, out=out, engine="dsl")
    second = scan_workspace(root=basic_repo_root, out=out, engine="dsl")

    assert first.cache_misses >= 1
    assert second.cache_hits >= 1


def test_custom_rule_source_forces_cache_miss(basic_repo_root: Path, tmp_path: Path) -> None:
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


@pytest.mark.parametrize(
    ("ip", "expected_score"),
    [
        ("192.168.1.1", 50),
        ("8.8.8.8", 82),
    ],
    ids=["private-lower", "public-higher"],
)
def test_ip_address_scoring(tmp_path: Path, ip: str, expected_score: int) -> None:
    path = _skill_file(
        tmp_path,
        f"---\nname: ip-test\n---\n# IP\nurl: http://{ip}/hook\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"NET_RAW_IP"}))
    findings = engine.run_all(skill_name="ip-test", parsed=parsed, config=config)
    assert len(findings) == 1
    assert findings[0].score == expected_score


def test_entropy_check_skips_short_values(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: entropy-test\n---\n# Entropy\nshort: abc\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"OPAQUE_BLOB"}))
    findings = engine.run_all(skill_name="entropy-test", parsed=parsed, config=config)
    assert len(findings) == 0


def test_typosquat_with_baseline(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: opena1-helper\n---\n# Typo\nA skill.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig(typosquat_baseline=("openai-helper",))
    engine = DslEngine(rule_ids=frozenset({"TYPOSQUAT"}))
    findings = engine.run_all(skill_name="opena1-helper", parsed=parsed, config=config)
    assert len(findings) == 1
    assert findings[0].score == 76


def test_typosquat_no_baseline(tmp_path: Path) -> None:
    path = _skill_file(tmp_path, "---\nname: test\n---\n# Test\nA skill.\n")
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TYPOSQUAT"}))
    findings = engine.run_all(skill_name="test", parsed=parsed, config=config)
    assert len(findings) == 0


def test_auth_requires_strong_hint(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: auth-test\n---\n# Auth\nConnect to the service and set up credentials.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"AUTH_CONNECTION"}))
    findings = engine.run_all(skill_name="auth-test", parsed=parsed, config=config)
    assert len(findings) == 0


def test_dynamic_schema_single_hit(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: dyn-test\n---\n# Dynamic\nBefore executing any tool, discover tools.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DYNAMIC_SCHEMA"}))
    findings = engine.run_all(skill_name="dyn-test", parsed=parsed, config=config)
    assert len(findings) == 1
    assert findings[0].score == 15


def test_tool_invocation_consolidates_to_one_finding(tmp_path: Path) -> None:
    """Multiple duplicate tokens produce one consolidated finding."""
    path = _skill_file(
        tmp_path,
        "---\nname: tool-test\n---\n"
        "RUBE_SEARCH_TOOLS\n"
        "RUBE_SEARCH_TOOLS\n"
        "MCP_LIST_TOOLS\n"
        "RUBE_SEARCH_TOOLS\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="tool-test", parsed=parsed, config=config)

    assert len(findings) == 1
    assert "2 tool invocation tokens" in findings[0].description
    assert "MCP_LIST_TOOLS" in findings[0].evidence.snippet
    assert "RUBE_SEARCH_TOOLS" in findings[0].evidence.snippet


def test_tool_invocation_detects_service_tokens(tmp_path: Path) -> None:
    """Service tokens like SLACK_SEND_MESSAGE are detected and consolidated."""
    path = _skill_file(
        tmp_path,
        "---\nname: tool-test\n---\n" "SLACK_SEND_MESSAGE\n" "STRIPE_CREATE_CHARGE\n" "USE_THIS_FORMAT\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="tool-test", parsed=parsed, config=config)

    assert len(findings) == 1
    assert "2 tool invocation tokens" in findings[0].description
    assert "SLACK_SEND_MESSAGE" in findings[0].evidence.snippet
    assert "STRIPE_CREATE_CHARGE" in findings[0].evidence.snippet


def test_tool_invocation_single_token_produces_one_finding(tmp_path: Path) -> None:
    """A single tool token produces exactly one finding."""
    path = _skill_file(
        tmp_path,
        "---\nname: single\n---\nRUBE_SEARCH_TOOLS\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="single", parsed=parsed, config=config)

    assert len(findings) == 1
    assert "1 tool invocation token" in findings[0].description
    assert "RUBE_SEARCH_TOOLS" in findings[0].evidence.snippet


def test_tool_invocation_destructive_tokens_score_higher(tmp_path: Path) -> None:
    """Skills with destructive tokens (DELETE, REMOVE) score higher than read-only."""
    dest_dir = tmp_path / "destructive"
    dest_dir.mkdir()
    destructive_path = _skill_file(
        dest_dir,
        "---\nname: destructive-test\n---\n" "GITHUB_DELETE_A_REPOSITORY\n" "GITHUB_MERGE_PULL_REQUEST\n",
    )
    read_dir = tmp_path / "read"
    read_dir.mkdir()
    read_path = _skill_file(
        read_dir,
        "---\nname: read-test\n---\n" "GITHUB_GET_A_REPOSITORY\n" "GITHUB_LIST_REPOSITORIES\n",
    )
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    destructive_parsed = parse_skill_markdown_file(destructive_path)
    destructive_findings = engine.run_all(
        skill_name="destructive-test",
        parsed=destructive_parsed,
        config=config,
    )

    read_parsed = parse_skill_markdown_file(read_path)
    read_findings = engine.run_all(
        skill_name="read-test",
        parsed=read_parsed,
        config=config,
    )

    assert len(destructive_findings) == 1
    assert len(read_findings) == 1
    assert destructive_findings[0].score > read_findings[0].score
    assert "destructive" in destructive_findings[0].description.lower()
    assert "read" in read_findings[0].description.lower()


def test_tool_invocation_write_tokens_score_between_destructive_and_read(tmp_path: Path) -> None:
    """Write tokens score higher than read-only but lower than destructive."""
    write_dir = tmp_path / "write"
    write_dir.mkdir()
    write_path = _skill_file(
        write_dir,
        "---\nname: write-test\n---\n" "SLACK_SEND_MESSAGE\n",
    )
    read_dir = tmp_path / "read"
    read_dir.mkdir()
    read_path = _skill_file(
        read_dir,
        "---\nname: read-test\n---\n" "SLACK_LIST_CHANNELS\n",
    )
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    write_parsed = parse_skill_markdown_file(write_path)
    write_findings = engine.run_all(skill_name="write-test", parsed=write_parsed, config=config)

    read_parsed = parse_skill_markdown_file(read_path)
    read_findings = engine.run_all(skill_name="read-test", parsed=read_parsed, config=config)

    assert len(write_findings) == 1
    assert len(read_findings) == 1
    assert write_findings[0].score > read_findings[0].score
    assert "write" in write_findings[0].description.lower()


def test_tool_invocation_tier_breakdown_in_description(tmp_path: Path) -> None:
    """Tier counts appear in the consolidated description."""
    path = _skill_file(
        tmp_path,
        "---\nname: mixed-test\n---\n"
        "GITHUB_DELETE_A_REPOSITORY\n"
        "GITHUB_CREATE_ISSUE\n"
        "GITHUB_GET_A_REPOSITORY\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="mixed-test", parsed=parsed, config=config)

    assert len(findings) == 1
    desc = findings[0].description
    assert "3 tool invocation tokens" in desc
    assert "1 destructive" in desc
    assert "1 write" in desc
    assert "1 read" in desc


def test_tool_invocation_top_n_overflow_in_snippet(tmp_path: Path) -> None:
    """Snippet shows top 5 tokens and overflow count for large token sets."""
    tokens = [f"RUBE_ACTION_{chr(65 + i)}" for i in range(8)]
    body = "\n".join(tokens)
    path = _skill_file(
        tmp_path,
        f"---\nname: overflow-test\n---\n{body}\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="overflow-test", parsed=parsed, config=config)

    assert len(findings) == 1
    assert "(+3 more)" in findings[0].evidence.snippet


def test_tool_invocation_score_capped_at_max(tmp_path: Path) -> None:
    """Consolidated score never exceeds TOOL_CONSOLIDATION_MAX_SCORE."""
    tokens = [f"GITHUB_DELETE_ITEM_{i}" for i in range(20)]
    body = "\n".join(tokens)
    path = _skill_file(
        tmp_path,
        f"---\nname: maxscore-test\n---\n{body}\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="maxscore-test", parsed=parsed, config=config)

    assert len(findings) == 1
    assert findings[0].score == 50


def test_tool_invocation_no_tokens_produces_no_findings(tmp_path: Path) -> None:
    """A skill with no matching tokens produces zero findings."""
    path = _skill_file(
        tmp_path,
        "---\nname: clean\n---\nNo tool tokens here.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="clean", parsed=parsed, config=config)

    assert len(findings) == 0


def test_tool_invocation_custom_tier_keywords(tmp_path: Path) -> None:
    """Custom tier keywords from config override defaults."""
    from razin.config import ToolTierConfig

    path = _skill_file(
        tmp_path,
        "---\nname: custom-tier\n---\n" "RUBE_CUSTOM_LAUNCH\n" "RUBE_CUSTOM_SCAN\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig(
        tool_tier_keywords=ToolTierConfig(
            destructive=("LAUNCH",),
            write=("SCAN",),
        ),
    )
    engine = DslEngine(rule_ids=frozenset({"TOOL_INVOCATION"}))

    findings = engine.run_all(skill_name="custom-tier", parsed=parsed, config=config)

    assert len(findings) == 1
    assert "1 destructive" in findings[0].description
    assert "1 write" in findings[0].description


def test_secret_ref_ignores_placeholder_values(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: secret-test\n---\n"
        "~~~yaml\n"
        "apiKey: your-api-key\n"
        "~~~\n"
        "password: CHANGEME\n"
        "apiKey: sk-live-abc123def456\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"SECRET_REF"}))

    findings = engine.run_all(skill_name="secret-test", parsed=parsed, config=config)

    assert len(findings) == 1
    assert findings[0].rule_id == "SECRET_REF"
    assert findings[0].evidence.line == 8
    assert "apiKey" in findings[0].description


def test_net_unknown_domain_uses_default_allowlist(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: domains\n---\n" "See https://github.com/example/repo for docs.\n",
    )
    parsed = parse_skill_markdown_file(path)
    engine = DslEngine(rule_ids=frozenset({"NET_UNKNOWN_DOMAIN"}))

    findings = engine.run_all(skill_name="domains", parsed=parsed, config=RazinConfig())
    assert len(findings) == 0


def test_net_unknown_domain_can_ignore_default_allowlist(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: domains\n---\n" "See https://github.com/example/repo for docs.\n",
    )
    parsed = parse_skill_markdown_file(path)
    engine = DslEngine(rule_ids=frozenset({"NET_UNKNOWN_DOMAIN"}))

    findings = engine.run_all(
        skill_name="domains",
        parsed=parsed,
        config=RazinConfig(ignore_default_allowlist=True),
    )
    assert len(findings) == 1
    assert "github.com" in findings[0].description


def test_mcp_required_fires_when_present(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: mcp-test\nrequires:\n  mcp: [server1]\n---\n# MCP\nDocs.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"MCP_REQUIRED"}))
    findings = engine.run_all(skill_name="mcp-test", parsed=parsed, config=config)
    assert len(findings) == 1
    assert findings[0].score == 28


def test_mcp_required_silent_when_absent(tmp_path: Path) -> None:
    path = _skill_file(tmp_path, "---\nname: no-mcp\n---\n# Test\nDocs.\n")
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"MCP_REQUIRED"}))
    findings = engine.run_all(skill_name="no-mcp", parsed=parsed, config=config)
    assert len(findings) == 0


def test_exec_fields_exact_match(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: exec-test\n---\n# Exec\ncommand: run me\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"EXEC_FIELDS"}))
    findings = engine.run_all(skill_name="exec-test", parsed=parsed, config=config)
    assert len(findings) == 1
    assert findings[0].score == 72


def test_exec_fields_no_false_positive(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: safe\n---\n# Safe\ncommander: no match\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"EXEC_FIELDS"}))
    findings = engine.run_all(skill_name="safe", parsed=parsed, config=config)
    assert len(findings) == 0


def test_exec_fields_run_prose_line_not_flagged(tmp_path: Path) -> None:
    path = _skill_file(
        tmp_path,
        "---\nname: safe\n---\n# Safe\nrun: this is a prose instruction\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"EXEC_FIELDS"}))
    findings = engine.run_all(skill_name="safe", parsed=parsed, config=config)
    assert len(findings) == 0


def test_rules_dir_not_found_fails_fast(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Rules directory does not exist"):
        DslEngine(rules_dir=tmp_path / "nonexistent")


def test_all_yaml_files_valid() -> None:
    """All bundled YAML rule files parse and compile without error."""
    engine = DslEngine()
    assert engine.rule_count == 15
    assert len(engine.rule_ids) == len(set(engine.rule_ids))


def test_schema_rejects_unknown_profile() -> None:
    rule = _minimal_rule()
    rule["profiles"] = {"enterprise": {"score_override": 80}}
    with pytest.raises(DslSchemaError, match="unknown profile"):
        validate_rule(rule, "<test>")


def test_schema_rejects_unknown_overlay_key() -> None:
    rule = _minimal_rule()
    rule["profiles"] = {"strict": {"boost": 10}}
    with pytest.raises(DslSchemaError, match="unknown keys"):
        validate_rule(rule, "<test>")


def test_schema_rejects_invalid_score_override() -> None:
    rule = _minimal_rule()
    rule["profiles"] = {"strict": {"score_override": 200}}
    with pytest.raises(DslSchemaError, match="score_override"):
        validate_rule(rule, "<test>")


def test_schema_accepts_valid_profiles() -> None:
    rule = _minimal_rule()
    rule["profiles"] = {
        "strict": {"score_override": 80},
        "audit": {"score_override": 0},
    }
    validate_rule(rule, "<test>")


def test_profile_override_changes_score(tmp_path: Path) -> None:
    """Write a custom rule with profile overlay and verify score changes."""
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
    """In replace mode, only custom rules are loaded (bundled excluded)."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_ONLY")

    engine = DslEngine(rules_dir=rules_dir, rules_mode="replace")

    assert engine.rule_count == 1
    assert engine.rule_ids == ["CUSTOM_ONLY"]


def test_overlay_mode_merges_bundled_and_custom(tmp_path: Path) -> None:
    """Overlay mode loads bundled rules plus custom, no-conflict."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_EXTRA")

    engine = DslEngine(rules_dir=rules_dir, rules_mode="overlay")

    assert "CUSTOM_EXTRA" in engine.rule_ids
    assert "AUTH_CONNECTION" in engine.rule_ids
    assert engine.rule_count > 1


def test_overlay_mode_with_rule_files(tmp_path: Path) -> None:
    """Overlay mode works with --rule-file too."""
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
    """Override policy lets custom rule replace bundled rule with same rule_id."""
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
    """Overlay without custom source just loads bundled rules."""
    engine = DslEngine(rules_mode="overlay")

    assert engine.rule_count == 15
    assert "AUTH_CONNECTION" in engine.rule_ids


def test_replace_mode_without_custom_uses_bundled() -> None:
    """Replace mode with no custom source falls back to bundled."""
    engine = DslEngine(rules_mode="replace")

    assert engine.rule_count == 15


def test_overlay_fingerprint_differs_from_replace(tmp_path: Path) -> None:
    """Fingerprint changes when rules_mode changes the effective rule set."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule_file(rules_dir / "custom.yaml", rule_id="CUSTOM_FP")

    replace_engine = DslEngine(rules_dir=rules_dir, rules_mode="replace")
    overlay_engine = DslEngine(rules_dir=rules_dir, rules_mode="overlay")

    assert replace_engine.fingerprint() != overlay_engine.fingerprint()


def test_overlay_override_fingerprint_differs_from_bundled(tmp_path: Path) -> None:
    """Override changes the effective rule set so fingerprint differs."""
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
