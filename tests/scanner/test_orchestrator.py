"""Tests for orchestrator helper functions."""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.exceptions import ConfigError
from razin.model import Evidence, FindingCandidate
from razin.scanner.pipeline.config_resolution import (
    normalize_domain_or_url,
    resolve_engine,
    resolve_rule_sources,
)
from razin.scanner.pipeline.conversion import (
    candidate_to_finding,
    deserialize_findings,
    suppress_redundant_candidates,
)
from razin.types import RuleOverrideConfig


def test_deserialize_findings_handles_invalid_payload() -> None:
    findings = deserialize_findings([{"id": "a", "evidence": "bad"}, "not-a-dict"])

    assert len(findings) == 1
    assert findings[0].id == "a"
    assert findings[0].evidence.path == ""


def test_normalize_domain_or_url_handles_domains_and_urls() -> None:
    assert normalize_domain_or_url("https://Example.COM/mcp") == "example.com"
    assert normalize_domain_or_url("example.com/") == "example.com"
    assert normalize_domain_or_url("  ") is None
    assert normalize_domain_or_url("http://") is None


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

    finding_a = candidate_to_finding("skill-a", first)
    finding_b = candidate_to_finding("skill-a", second)

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

    finding_a = candidate_to_finding("skill-a", key_split)
    finding_b = candidate_to_finding("skill-a", env_split)

    assert finding_a.id == finding_b.id


def test_candidate_to_finding_uses_profile_thresholds() -> None:
    candidate = FindingCandidate(
        rule_id="SECRET_REF",
        score=75,
        confidence="high",
        title="Secret-like key in config",
        description="Key 'token' appears to store or reference sensitive credentials.",
        evidence=Evidence(path="/tmp/SKILL.md", line=7, snippet="token: ${API_TOKEN}"),
        recommendation="Store secrets in secret managers and avoid embedding them in config.",
    )

    balanced = candidate_to_finding("skill-a", candidate, high_severity_min=80, medium_severity_min=50)
    strict = candidate_to_finding("skill-a", candidate, high_severity_min=70, medium_severity_min=40)

    assert balanced.severity == "medium"
    assert strict.severity == "high"


def test_candidate_to_finding_propagates_classification() -> None:
    """Finding classification is copied from candidate metadata."""
    candidate = FindingCandidate(
        rule_id="MCP_REQUIRED",
        score=28,
        confidence="high",
        title="MCP requirement declared",
        description="Frontmatter requires MCP connectivity for this skill.",
        evidence=Evidence(path="/tmp/SKILL.md", line=3, snippet="requires: mcp"),
        recommendation="Restrict MCP server access to approved endpoints.",
        classification="informational",
    )

    finding = candidate_to_finding("skill-a", candidate)

    assert finding.classification == "informational"


def test_candidate_to_finding_applies_rule_override_cap() -> None:
    """Rule override caps both severity and score and stores audit metadata."""
    candidate = FindingCandidate(
        rule_id="SECRET_REF",
        score=90,
        confidence="high",
        title="Secret-like key in config",
        description="Sensitive token referenced in config.",
        evidence=Evidence(path="/tmp/SKILL.md", line=7, snippet="token: ${API_TOKEN}"),
        recommendation="Store secrets in secret manager.",
    )

    finding = candidate_to_finding(
        "skill-a",
        candidate,
        rule_override=RuleOverrideConfig(max_severity="medium"),
        high_severity_min=80,
        medium_severity_min=50,
    )

    assert finding.severity == "medium"
    assert finding.score == 79
    assert finding.severity_override is not None
    assert finding.severity_override.original == "high"
    assert finding.severity_override.applied == "medium"
    assert finding.severity_override.reason == "rule_override"


def test_candidate_to_finding_applies_rule_override_bump() -> None:
    """Rule override can raise a low severity finding to the configured minimum."""
    candidate = FindingCandidate(
        rule_id="SECRET_REF",
        score=20,
        confidence="high",
        title="Secret-like key in config",
        description="Sensitive token referenced in config.",
        evidence=Evidence(path="/tmp/SKILL.md", line=7, snippet="token: ${API_TOKEN}"),
        recommendation="Store secrets in secret manager.",
    )

    finding = candidate_to_finding(
        "skill-a",
        candidate,
        rule_override=RuleOverrideConfig(min_severity="high"),
        high_severity_min=80,
        medium_severity_min=50,
    )

    assert finding.severity == "high"
    assert finding.score == 80
    assert finding.severity_override is not None
    assert finding.severity_override.original == "low"
    assert finding.severity_override.applied == "high"


def test_suppress_redundant_candidates_keeps_mcp_and_removes_overlapping_unknown_domain() -> None:
    shared_evidence = Evidence(path="/tmp/SKILL.md", line=9, snippet="https://rube.app/mcp")
    other_evidence = Evidence(path="/tmp/SKILL.md", line=12, snippet="https://evil.example.net/docs")

    candidates = [
        FindingCandidate(
            rule_id="MCP_ENDPOINT",
            score=70,
            confidence="high",
            title="MCP endpoint in docs",
            description="Documentation references MCP endpoint 'https://rube.app/mcp'.",
            evidence=shared_evidence,
            recommendation="Constrain MCP endpoints with allowlists.",
        ),
        FindingCandidate(
            rule_id="NET_UNKNOWN_DOMAIN",
            score=35,
            confidence="low",
            title="Non-allowlisted domain in config",
            description="Configuration references external domain 'rube.app'.",
            evidence=shared_evidence,
            recommendation="Restrict outbound domains with allowlists.",
        ),
        FindingCandidate(
            rule_id="NET_UNKNOWN_DOMAIN",
            score=35,
            confidence="low",
            title="Non-allowlisted domain in config",
            description="Configuration references external domain 'evil.example.net'.",
            evidence=other_evidence,
            recommendation="Restrict outbound domains with allowlists.",
        ),
    ]

    suppressed = suppress_redundant_candidates(candidates)

    assert len(suppressed) == 2
    assert any(candidate.rule_id == "MCP_ENDPOINT" for candidate in suppressed)
    assert any(candidate.rule_id == "NET_UNKNOWN_DOMAIN" and candidate.evidence.line == 12 for candidate in suppressed)


def test_suppress_redundant_keeps_denylist_net_doc_domain() -> None:
    """High-severity NET_DOC_DOMAIN (denylist, score 80) is not suppressed by MCP_ENDPOINT (score 70)."""
    shared_evidence = Evidence(path="/tmp/SKILL.md", line=5, snippet="https://evil.attacker.io/mcp")

    candidates = [
        FindingCandidate(
            rule_id="MCP_ENDPOINT",
            score=70,
            confidence="high",
            title="MCP endpoint in docs",
            description="Documentation references MCP endpoint 'https://evil.attacker.io/mcp'.",
            evidence=shared_evidence,
            recommendation="Constrain MCP endpoints with allowlists.",
        ),
        FindingCandidate(
            rule_id="NET_DOC_DOMAIN",
            score=80,
            confidence="high",
            title="Denylisted domain in docs",
            description="Documentation references 'evil.attacker.io', which is denylisted.",
            evidence=shared_evidence,
            recommendation="Remove or replace denylisted domains.",
        ),
    ]

    suppressed = suppress_redundant_candidates(candidates)

    assert len(suppressed) == 2
    assert any(c.rule_id == "MCP_ENDPOINT" for c in suppressed)
    assert any(c.rule_id == "NET_DOC_DOMAIN" and c.score == 80 for c in suppressed)


def test_suppress_redundant_still_drops_low_net_doc_domain() -> None:
    """Low-severity NET_DOC_DOMAIN (score 15) is suppressed by MCP_ENDPOINT on same line."""
    shared_evidence = Evidence(path="/tmp/SKILL.md", line=5, snippet="https://unknown.io/mcp")

    candidates = [
        FindingCandidate(
            rule_id="MCP_ENDPOINT",
            score=70,
            confidence="high",
            title="MCP endpoint in docs",
            description="Documentation references MCP endpoint 'https://unknown.io/mcp'.",
            evidence=shared_evidence,
            recommendation="Constrain MCP endpoints with allowlists.",
        ),
        FindingCandidate(
            rule_id="NET_DOC_DOMAIN",
            score=15,
            confidence="low",
            title="Non-allowlisted domain in docs",
            description="Documentation references external domain 'unknown.io'.",
            evidence=shared_evidence,
            recommendation="Review documentation URLs.",
        ),
    ]

    suppressed = suppress_redundant_candidates(candidates)

    assert len(suppressed) == 1
    assert suppressed[0].rule_id == "MCP_ENDPOINT"
    assert resolve_engine("dsl") == "dsl"
    assert resolve_engine(" DSL ") == "dsl"


def test_resolve_engine_rejects_invalid() -> None:
    with pytest.raises(ConfigError, match="supports only 'dsl'"):
        resolve_engine("invalid")


@pytest.mark.parametrize("value", ["legacy", "optionc", "default"])
def test_resolve_engine_rejects_removed_values(value: str) -> None:
    with pytest.raises(ConfigError, match="Removed values"):
        resolve_engine(value)


def test_resolve_rule_sources_defaults_to_bundled() -> None:
    resolved_dir, resolved_files = resolve_rule_sources(rules_dir=None, rule_files=None)

    assert resolved_dir is None
    assert resolved_files is None


def test_resolve_rule_sources_rejects_conflicting_modes(tmp_path: Path) -> None:
    rule_file = tmp_path / "custom.yaml"
    rule_file.write_text("rule_id: CUSTOM\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="either --rules-dir or --rule-file"):
        resolve_rule_sources(rules_dir=tmp_path, rule_files=(rule_file,))


def test_resolve_rule_sources_resolves_directory_mode(tmp_path: Path) -> None:
    resolved_dir, resolved_files = resolve_rule_sources(rules_dir=tmp_path, rule_files=None)

    assert resolved_dir == tmp_path.resolve()
    assert resolved_files is None


def test_resolve_rule_sources_rejects_invalid_file_extension(tmp_path: Path) -> None:
    rule_file = tmp_path / "custom.yml"
    rule_file.write_text("rule_id: CUSTOM\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="\\.yaml"):
        resolve_rule_sources(rules_dir=None, rule_files=(rule_file,))


def test_resolve_rule_sources_sorts_rule_files(tmp_path: Path) -> None:
    first = tmp_path / "b.yaml"
    first.write_text("rule_id: RULE_B\n", encoding="utf-8")
    second = tmp_path / "a.yaml"
    second.write_text("rule_id: RULE_A\n", encoding="utf-8")

    resolved_dir, resolved_files = resolve_rule_sources(rules_dir=None, rule_files=(first, second))

    assert resolved_dir is None
    assert resolved_files == tuple(sorted((first.resolve(), second.resolve())))
