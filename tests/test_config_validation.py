"""Tests for config and DSL rule validation (error codes, messages, ordering)."""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.cli.main import main
from razin.config import _suggest_key, load_config, validate_config_file
from razin.constants.validation import (
    ALLOWED_CONFIG_KEYS,
    CFG001,
    CFG002,
    CFG003,
    CFG004,
    CFG005,
    CFG006,
    CFG007,
    CFG008,
    CFG009,
    CFG010,
    RULE001,
    RULE002,
    RULE003,
    RULE004,
    RULE005,
    RULE006,
    RULE007,
    RULE008,
    RULE009,
)
from razin.dsl.validation import validate_rule_sources
from razin.exceptions import ConfigError
from razin.exceptions.validation import ValidationError, format_errors, sort_errors
from razin.validation import preflight_validate


def _minimal_rule_yaml(
    *,
    rule_id: str = "TEST_RULE_001",
    version: int = 1,
    confidence: str = "high",
    base_score: int = 50,
    strategy: str = "keyword_in_text",
    source: str = "raw_text",
    extra_keys: str = "",
) -> str:
    """Build a minimal valid DSL v1 rule YAML string."""
    return (
        f"rule_id: {rule_id}\n"
        f"version: {version}\n"
        "metadata:\n"
        "  title: Test Rule\n"
        "  description: A test rule.\n"
        "  recommendation: Fix it.\n"
        f"  confidence: {confidence}\n"
        "scoring:\n"
        f"  base_score: {base_score}\n"
        "match:\n"
        f"  source: {source}\n"
        f"  strategy: {strategy}\n"
        "  params:\n"
        "    keywords:\n"
        "      - test_keyword\n"
        f"{extra_keys}"
    )


def _write_config(tmp_path: Path, content: str) -> Path:
    cfg = tmp_path / "razin.yaml"
    cfg.write_text(content, encoding="utf-8")
    return cfg


def test_validation_error_format_with_all_fields() -> None:
    err = ValidationError(
        code="CFG004",
        path="/repo/razin.yaml",
        field="mcp_allowlst",
        message="unknown key `mcp_allowlst`",
        hint="did you mean `mcp_allowlist_domains`?",
        line=20,
        column=1,
    )
    assert err.format() == (
        "[CFG004] /repo/razin.yaml:20:1 unknown key `mcp_allowlst` (did you mean `mcp_allowlist_domains`?)"
    )


def test_validation_error_format_without_optional_fields() -> None:
    err = ValidationError(
        code="CFG003",
        path="/repo/razin.yaml",
        field="",
        message="config must be a YAML mapping, got list",
    )
    assert err.format() == "[CFG003] /repo/razin.yaml config must be a YAML mapping, got list"


def test_sort_errors_is_deterministic() -> None:
    errs = [
        ValidationError(code="CFG005", path="/b.yaml", field="x", message="m"),
        ValidationError(code="CFG004", path="/a.yaml", field="y", message="m"),
        ValidationError(code="CFG004", path="/a.yaml", field="x", message="m"),
    ]
    sorted_errs = sort_errors(errs)
    assert [e.code for e in sorted_errs] == ["CFG004", "CFG004", "CFG005"]
    assert [e.field for e in sorted_errs] == ["x", "y", "x"]


def test_format_errors_combines_sorted_lines() -> None:
    errs = [
        ValidationError(code="CFG005", path="/b.yaml", field="x", message="bad type"),
        ValidationError(code="CFG004", path="/a.yaml", field="y", message="unknown"),
    ]
    lines = format_errors(errs).strip().split("\n")
    assert len(lines) == 2
    assert lines[0].startswith("[CFG004]")
    assert lines[1].startswith("[CFG005]")


@pytest.mark.parametrize(
    ("unknown", "expected_in_hint"),
    [
        pytest.param("mcp_allowlst", "mcp_allowlist_domains", id="close-match"),
        pytest.param("zzzzz_totally_wrong", "", id="no-match"),
    ],
)
def test_suggest_key(unknown: str, expected_in_hint: str) -> None:
    hint = _suggest_key(unknown, ALLOWED_CONFIG_KEYS)
    if expected_in_hint:
        assert expected_in_hint in hint
    else:
        assert hint == ""


def test_missing_default_config_returns_no_errors(tmp_path: Path) -> None:
    assert validate_config_file(tmp_path) == []


def test_missing_explicit_config_returns_cfg001(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.yaml"
    errors = validate_config_file(tmp_path, missing, config_explicit=True)
    assert len(errors) == 1
    assert errors[0].code == CFG001


@pytest.mark.parametrize(
    ("yaml_content", "expected_code"),
    [
        pytest.param(":\n  - :\n  bad: [", CFG002, id="invalid-yaml"),
        pytest.param("- item1\n- item2\n", CFG003, id="non-mapping"),
        pytest.param("profile: strictest\n", CFG006, id="invalid-profile-enum"),
        pytest.param("max_file_mb: true\n", CFG005, id="bool-max-file-mb"),
        pytest.param("max_file_mb: -1\n", CFG007, id="negative-max-file-mb"),
        pytest.param("ignore_default_allowlist: maybe\n", CFG005, id="non-bool-ignore-allowlist"),
        pytest.param("allowlist_domains: 123\n", CFG005, id="non-list-domains"),
        pytest.param("detectors: notamap\n", CFG009, id="detectors-not-mapping"),
        pytest.param("typosquat: 42\n", CFG009, id="typosquat-not-mapping"),
    ],
)
def test_config_file_rejects_invalid_values(tmp_path: Path, yaml_content: str, expected_code: str) -> None:
    _write_config(tmp_path, yaml_content)
    errors = validate_config_file(tmp_path)
    assert any(e.code == expected_code for e in errors)


def test_unknown_key_returns_cfg004_with_field_name(tmp_path: Path) -> None:
    _write_config(tmp_path, "mcp_allowlst: []\n")
    errors = validate_config_file(tmp_path)
    cfg004 = [e for e in errors if e.code == CFG004]
    assert len(cfg004) == 1
    assert "mcp_allowlst" in cfg004[0].message


def test_unknown_key_includes_typo_suggestion(tmp_path: Path) -> None:
    _write_config(tmp_path, "mcp_allowlist_domain: []\n")
    errors = validate_config_file(tmp_path)
    cfg004 = [e for e in errors if e.code == CFG004]
    assert len(cfg004) == 1
    assert "did you mean" in cfg004[0].hint


def test_detectors_unknown_subkey_returns_cfg004(tmp_path: Path) -> None:
    _write_config(tmp_path, "detectors:\n  activate: [X]\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG004 and "detectors" in e.field for e in errors)


def test_contradictory_detectors_returns_cfg008(tmp_path: Path) -> None:
    _write_config(tmp_path, "detectors:\n  enabled:\n    - SECRET_REF\n  disabled:\n    - SECRET_REF\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG008 for e in errors)


def test_typosquat_unknown_subkey_returns_cfg004(tmp_path: Path) -> None:
    _write_config(tmp_path, "typosquat:\n  basline: []\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG004 and "typosquat" in e.field for e in errors)


def test_tool_tier_unknown_subkey_returns_cfg004(tmp_path: Path) -> None:
    """Unknown subkey under tool_tier_keywords is flagged."""
    _write_config(tmp_path, "tool_tier_keywords:\n  destuctive: []\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG004 and "tool_tier_keywords" in e.field for e in errors)


def test_tool_tier_invalid_type_returns_cfg009(tmp_path: Path) -> None:
    """Non-mapping tool_tier_keywords value is flagged."""
    _write_config(tmp_path, "tool_tier_keywords: invalid\n")
    errors = validate_config_file(tmp_path)
    assert any(e.code == CFG009 and "tool_tier_keywords" in e.field for e in errors)


def test_tool_tier_valid_config_returns_no_errors(tmp_path: Path) -> None:
    """Valid tool_tier_keywords produces no errors."""
    _write_config(
        tmp_path,
        "tool_tier_keywords:\n  destructive:\n    - LAUNCH\n  write:\n    - DEPLOY\n",
    )
    assert validate_config_file(tmp_path) == []


@pytest.mark.parametrize(
    "yaml_content",
    [
        pytest.param("profile: strict\nmax_file_mb: 5\nallowlist_domains:\n  - api.example.com\n", id="full-valid"),
        pytest.param("", id="empty-file"),
    ],
)
def test_valid_config_returns_no_errors(tmp_path: Path, yaml_content: str) -> None:
    _write_config(tmp_path, yaml_content)
    assert validate_config_file(tmp_path) == []


def test_multiple_config_errors_collected(tmp_path: Path) -> None:
    _write_config(tmp_path, "profile: wrong\nunknown_key: 1\nmax_file_mb: -5\n")
    codes = {e.code for e in validate_config_file(tmp_path)}
    assert {CFG004, CFG006, CFG007} <= codes


def test_rule_source_conflict_returns_rule009(tmp_path: Path) -> None:
    errors = validate_rule_sources(rules_dir=tmp_path, rule_files=(tmp_path / "a.yaml",))
    assert len(errors) == 1
    assert errors[0].code == RULE009


@pytest.mark.parametrize(
    ("setup", "expected_code"),
    [
        pytest.param("missing_file", RULE001, id="missing-rule-file"),
        pytest.param("bad_extension", RULE002, id="bad-extension"),
        pytest.param("invalid_yaml", RULE003, id="invalid-yaml"),
        pytest.param("non_mapping", RULE004, id="non-mapping"),
        pytest.param("missing_dir", RULE001, id="missing-rules-dir"),
    ],
)
def test_rule_source_structural_errors(tmp_path: Path, setup: str, expected_code: str) -> None:
    if setup == "missing_file":
        errors = validate_rule_sources(rule_files=(tmp_path / "missing.yaml",))
    elif setup == "bad_extension":
        txt = tmp_path / "rule.txt"
        txt.write_text("rule_id: x\n", encoding="utf-8")
        errors = validate_rule_sources(rule_files=(txt,))
    elif setup == "invalid_yaml":
        bad = tmp_path / "bad.yaml"
        bad.write_text(":\n  - :\n  [", encoding="utf-8")
        errors = validate_rule_sources(rule_files=(bad,))
    elif setup == "non_mapping":
        lst = tmp_path / "list.yaml"
        lst.write_text("- item\n", encoding="utf-8")
        errors = validate_rule_sources(rule_files=(lst,))
    else:
        errors = validate_rule_sources(rules_dir=tmp_path / "nonexistent")
    assert any(e.code == expected_code for e in errors)


def test_unknown_rule_top_key_returns_rule005(tmp_path: Path) -> None:
    rule = tmp_path / "r.yaml"
    rule.write_text(_minimal_rule_yaml(extra_keys="bogus_key: 1\n"), encoding="utf-8")
    errors = validate_rule_sources(rule_files=(rule,))
    assert any(e.code == RULE005 for e in errors)


def test_missing_required_rule_field_returns_rule006(tmp_path: Path) -> None:
    rule = tmp_path / "r.yaml"
    rule.write_text("rule_id: test\nversion: 1\n", encoding="utf-8")
    errors = validate_rule_sources(rule_files=(rule,))
    assert any(e.code == RULE006 for e in errors)


@pytest.mark.parametrize(
    ("override", "field_match"),
    [
        pytest.param({"version": 2}, "version", id="invalid-version"),
        pytest.param({"confidence": "extreme"}, "confidence", id="invalid-confidence"),
        pytest.param({"base_score": 200}, "base_score", id="invalid-base-score"),
        pytest.param({"strategy": "magic_scan"}, "strategy", id="invalid-strategy"),
    ],
)
def test_invalid_rule_field_value_returns_rule007(
    tmp_path: Path, override: dict[str, object], field_match: str
) -> None:
    rule = tmp_path / "r.yaml"
    rule.write_text(_minimal_rule_yaml(**override), encoding="utf-8")  # type: ignore[arg-type]
    errors = validate_rule_sources(rule_files=(rule,))
    assert any(e.code == RULE007 and field_match in e.field for e in errors)


def test_duplicate_rule_id_returns_rule008(tmp_path: Path) -> None:
    content = _minimal_rule_yaml(rule_id="DUP_RULE")
    (tmp_path / "r1.yaml").write_text(content, encoding="utf-8")
    (tmp_path / "r2.yaml").write_text(content, encoding="utf-8")
    errors = validate_rule_sources(rule_files=(tmp_path / "r1.yaml", tmp_path / "r2.yaml"))
    rule008 = [e for e in errors if e.code == RULE008]
    assert len(rule008) == 1
    assert "DUP_RULE" in rule008[0].message
    assert "first defined in" in rule008[0].hint


def test_bundled_rules_only_returns_no_errors() -> None:
    assert validate_rule_sources() == []


def test_valid_rule_returns_no_errors(tmp_path: Path) -> None:
    rule = tmp_path / "good.yaml"
    rule.write_text(_minimal_rule_yaml(), encoding="utf-8")
    assert validate_rule_sources(rule_files=(rule,)) == []


def test_preflight_valid_returns_empty(tmp_path: Path) -> None:
    _write_config(tmp_path, "profile: balanced\n")
    assert preflight_validate(root=tmp_path) == []


def test_preflight_nonexistent_root_returns_cfg010(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    errors = preflight_validate(root=missing)
    assert len(errors) == 1
    assert errors[0].code == CFG010


def test_preflight_combines_config_and_rule_errors(tmp_path: Path) -> None:
    _write_config(tmp_path, "bogus_key: true\n")
    bad_rule = tmp_path / "bad.yaml"
    bad_rule.write_text("- list\n", encoding="utf-8")
    codes = {e.code for e in preflight_validate(root=tmp_path, rule_files=(bad_rule,))}
    assert CFG004 in codes
    assert RULE004 in codes


def test_preflight_deterministic_ordering(tmp_path: Path) -> None:
    _write_config(tmp_path, "profile: wrong\nunknown: 1\nmax_file_mb: -1\n")
    errors = preflight_validate(root=tmp_path)
    assert errors == sort_errors(errors)
    errors2 = preflight_validate(root=tmp_path)
    assert [e.code for e in errors] == [e.code for e in errors2]


def test_validate_config_cli_valid_exits_zero(tmp_path: Path) -> None:
    _write_config(tmp_path, "profile: balanced\n")
    assert main(["validate-config", "--root", str(tmp_path)]) == 0


def test_validate_config_cli_no_file_exits_zero(tmp_path: Path) -> None:
    assert main(["validate-config", "--root", str(tmp_path)]) == 0


@pytest.mark.parametrize(
    ("setup", "extra_args"),
    [
        pytest.param("missing_config", [], id="missing-explicit-config"),
        pytest.param("unknown_key", [], id="unknown-config-key"),
        pytest.param("missing_rule", [], id="missing-rule-file"),
    ],
)
def test_validate_config_cli_invalid_exits_two(tmp_path: Path, setup: str, extra_args: list[str]) -> None:
    args = ["validate-config", "--root", str(tmp_path)]
    if setup == "missing_config":
        args.extend(["--config", str(tmp_path / "gone.yaml")])
    elif setup == "unknown_key":
        _write_config(tmp_path, "bogus: 1\n")
    elif setup == "missing_rule":
        args.extend(["--rule-file", str(tmp_path / "nonexistent.yaml")])
    assert main(args) == 2


def test_validate_config_cli_prints_valid_on_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_config(tmp_path, "profile: strict\n")
    assert main(["validate-config", "--root", str(tmp_path)]) == 0
    assert "valid" in capsys.readouterr().out.lower()


def test_validate_config_cli_prints_error_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_config(tmp_path, "bogus: 1\n")
    assert main(["validate-config", "--root", str(tmp_path)]) == 2
    assert "CFG004" in capsys.readouterr().err


def test_validate_config_cli_nonexistent_root_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "no_such_dir"
    assert main(["validate-config", "--root", str(missing)]) == 2
    assert "CFG010" in capsys.readouterr().err


def test_scan_preflight_rejects_invalid_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_config(tmp_path, "bogus_key: 1\n")
    assert main(["scan", "--root", str(tmp_path)]) == 2
    assert "CFG004" in capsys.readouterr().err


def test_scan_preflight_rejects_missing_explicit_config(tmp_path: Path) -> None:
    assert main(["scan", "--root", str(tmp_path), "--config", str(tmp_path / "gone.yaml")]) == 2


def test_load_config_explicit_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Config file not found"):
        load_config(tmp_path, config_path=tmp_path / "gone.yaml")


def test_load_config_default_missing_returns_defaults(tmp_path: Path) -> None:
    assert load_config(tmp_path).profile == "balanced"
