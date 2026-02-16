"""Tests for DSL schema validation and rule compilation."""

from __future__ import annotations

import pytest

from razin.dsl import DslEngine
from razin.dsl.compiler import CompiledRule, compile_rule
from razin.dsl.schema import validate_rule
from razin.exceptions.dsl import DslSchemaError

from .conftest import _minimal_rule


def test_valid_minimal_rule() -> None:
    """Minimal valid rule passes schema validation."""
    validate_rule(_minimal_rule(), "<test>")


def test_rejects_unknown_top_key() -> None:
    """Unknown top-level keys are rejected."""
    with pytest.raises(DslSchemaError, match="unknown top-level keys"):
        validate_rule(_minimal_rule(bogus="bad"), "<test>")


def test_rejects_missing_rule_id() -> None:
    """Missing rule_id is rejected."""
    rule = _minimal_rule()
    del rule["rule_id"]
    with pytest.raises(DslSchemaError, match="missing required key 'rule_id'"):
        validate_rule(rule, "<test>")


def test_rejects_wrong_version() -> None:
    """Wrong version value is rejected."""
    with pytest.raises(DslSchemaError, match="version"):
        validate_rule(_minimal_rule(version=2), "<test>")


def test_rejects_unknown_strategy() -> None:
    """Unknown match.strategy is rejected."""
    rule = _minimal_rule()
    rule["match"]["strategy"] = "hacks"
    with pytest.raises(DslSchemaError, match="match.strategy"):
        validate_rule(rule, "<test>")


def test_rejects_invalid_confidence() -> None:
    """Invalid confidence value is rejected."""
    rule = _minimal_rule()
    rule["metadata"]["confidence"] = "very_high"
    with pytest.raises(DslSchemaError, match="confidence"):
        validate_rule(rule, "<test>")


def test_rejects_out_of_range_score() -> None:
    """Out-of-range base_score is rejected."""
    rule = _minimal_rule()
    rule["scoring"]["base_score"] = 150
    with pytest.raises(DslSchemaError, match="base_score"):
        validate_rule(rule, "<test>")


def test_rejects_invalid_source() -> None:
    """Invalid match.source is rejected."""
    rule = _minimal_rule()
    rule["match"]["source"] = "network"
    with pytest.raises(DslSchemaError, match="match.source"):
        validate_rule(rule, "<test>")


def test_rejects_non_bool_dedupe() -> None:
    """Non-bool dedupe value is rejected."""
    with pytest.raises(DslSchemaError, match="dedupe"):
        validate_rule(_minimal_rule(dedupe="yes"), "<test>")


def test_compile_minimal_rule() -> None:
    """Compiler produces CompiledRule with correct fields from minimal input."""
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
    """Compiler uses public_rule_id when provided."""
    compiled = compile_rule(_minimal_rule(public_rule_id="PUBLIC_RULE"), "<test>")
    assert compiled.rule_id == "TEST_RULE"
    assert compiled.public_rule_id == "PUBLIC_RULE"


def test_compile_rejects_unregistered_strategy() -> None:
    """Compiler rejects an unknown strategy name."""
    rule = _minimal_rule()
    rule["match"]["strategy"] = "hacks"
    with pytest.raises(DslSchemaError):
        compile_rule(rule, "<test>")


def test_all_yaml_files_valid() -> None:
    """All bundled YAML rule files parse and compile without error."""
    engine = DslEngine()
    assert engine.rule_count == 18
    assert len(engine.rule_ids) == len(set(engine.rule_ids))


def test_schema_rejects_unknown_profile() -> None:
    """Unknown profile name in profiles block is rejected."""
    rule = _minimal_rule()
    rule["profiles"] = {"enterprise": {"score_override": 80}}
    with pytest.raises(DslSchemaError, match="unknown profile"):
        validate_rule(rule, "<test>")


def test_schema_rejects_unknown_overlay_key() -> None:
    """Unknown overlay key in profiles block is rejected."""
    rule = _minimal_rule()
    rule["profiles"] = {"strict": {"boost": 10}}
    with pytest.raises(DslSchemaError, match="unknown keys"):
        validate_rule(rule, "<test>")


def test_schema_rejects_invalid_score_override() -> None:
    """Invalid score_override value in profiles block is rejected."""
    rule = _minimal_rule()
    rule["profiles"] = {"strict": {"score_override": 200}}
    with pytest.raises(DslSchemaError, match="score_override"):
        validate_rule(rule, "<test>")


def test_schema_accepts_valid_profiles() -> None:
    """Valid profile overlays pass schema validation."""
    rule = _minimal_rule()
    rule["profiles"] = {
        "strict": {"score_override": 80},
        "audit": {"score_override": 0},
    }
    validate_rule(rule, "<test>")
