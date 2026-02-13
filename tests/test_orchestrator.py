"""Tests for orchestrator helper functions."""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.exceptions import ConfigError
from razin.model import Evidence, FindingCandidate
from razin.scanner.orchestrator import (
    _candidate_to_finding,
    _deserialize_findings,
    _normalize_domain_or_url,
    _resolve_engine,
    _resolve_rule_sources,
)


def test_deserialize_findings_handles_invalid_payload() -> None:
    findings = _deserialize_findings([{"id": "a", "evidence": "bad"}, "not-a-dict"])

    assert len(findings) == 1
    assert findings[0].id == "a"
    assert findings[0].evidence.path == ""


def test_normalize_domain_or_url_handles_domains_and_urls() -> None:
    assert _normalize_domain_or_url("https://Example.COM/mcp") == "example.com"
    assert _normalize_domain_or_url("example.com/") == "example.com"
    assert _normalize_domain_or_url("  ") is None
    assert _normalize_domain_or_url("http://") is None


def test_candidate_to_finding_id_changes_with_description() -> None:
    evidence = Evidence(path="/tmp/SKILL.md", line=10, snippet="Use RUBE_SEARCH")
    first = FindingCandidate(
        rule_id="TOOL_INVOCATION",
        score=62,
        confidence="medium",
        title="Tool invocation token in docs",
        description="Token A",
        evidence=evidence,
        recommendation="Review tool permissions.",
    )
    second = FindingCandidate(
        rule_id="TOOL_INVOCATION",
        score=62,
        confidence="medium",
        title="Tool invocation token in docs",
        description="Token B",
        evidence=evidence,
        recommendation="Review tool permissions.",
    )

    finding_a = _candidate_to_finding("skill-a", first)
    finding_b = _candidate_to_finding("skill-a", second)

    assert finding_a.id != finding_b.id


def test_candidate_to_finding_id_uses_public_rule_id() -> None:
    evidence = Evidence(path="/tmp/SKILL.md", line=7, snippet="token: ${API_TOKEN}")
    key_split = FindingCandidate(
        rule_id="SECRET_REF",
        score=74,
        confidence="high",
        title="Secret-like key in config",
        description="Key 'token' appears to store or reference sensitive credentials.",
        evidence=evidence,
        recommendation="Store secrets in secret managers and avoid embedding them in config.",
        internal_rule_id="SECRET_REF_KEYS",
    )
    env_split = FindingCandidate(
        rule_id="SECRET_REF",
        score=74,
        confidence="high",
        title="Secret-like key in config",
        description="Key 'token' appears to store or reference sensitive credentials.",
        evidence=evidence,
        recommendation="Store secrets in secret managers and avoid embedding them in config.",
        internal_rule_id="SECRET_REF",
    )

    finding_a = _candidate_to_finding("skill-a", key_split)
    finding_b = _candidate_to_finding("skill-a", env_split)

    assert finding_a.id == finding_b.id


def test_resolve_engine_accepts_dsl() -> None:
    assert _resolve_engine("dsl") == "dsl"
    assert _resolve_engine(" DSL ") == "dsl"


def test_resolve_engine_rejects_invalid() -> None:
    with pytest.raises(ConfigError, match="supports only 'dsl'"):
        _resolve_engine("invalid")


@pytest.mark.parametrize("value", ["legacy", "optionc", "default"])
def test_resolve_engine_rejects_removed_values(value: str) -> None:
    with pytest.raises(ConfigError, match="Removed values"):
        _resolve_engine(value)


def test_resolve_rule_sources_defaults_to_bundled() -> None:
    resolved_dir, resolved_files = _resolve_rule_sources(rules_dir=None, rule_files=None)

    assert resolved_dir is None
    assert resolved_files is None


def test_resolve_rule_sources_rejects_conflicting_modes(tmp_path: Path) -> None:
    rule_file = tmp_path / "custom.yaml"
    rule_file.write_text("rule_id: CUSTOM\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="either --rules-dir or --rule-file"):
        _resolve_rule_sources(rules_dir=tmp_path, rule_files=(rule_file,))


def test_resolve_rule_sources_resolves_directory_mode(tmp_path: Path) -> None:
    resolved_dir, resolved_files = _resolve_rule_sources(rules_dir=tmp_path, rule_files=None)

    assert resolved_dir == tmp_path.resolve()
    assert resolved_files is None


def test_resolve_rule_sources_rejects_invalid_file_extension(tmp_path: Path) -> None:
    rule_file = tmp_path / "custom.yml"
    rule_file.write_text("rule_id: CUSTOM\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="\\.yaml"):
        _resolve_rule_sources(rules_dir=None, rule_files=(rule_file,))


def test_resolve_rule_sources_sorts_rule_files(tmp_path: Path) -> None:
    first = tmp_path / "b.yaml"
    first.write_text("rule_id: RULE_B\n", encoding="utf-8")
    second = tmp_path / "a.yaml"
    second.write_text("rule_id: RULE_A\n", encoding="utf-8")

    resolved_dir, resolved_files = _resolve_rule_sources(rules_dir=None, rule_files=(first, second))

    assert resolved_dir is None
    assert resolved_files == tuple(sorted((first.resolve(), second.resolve())))
