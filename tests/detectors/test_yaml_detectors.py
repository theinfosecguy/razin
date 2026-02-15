"""Tests for YAML-defined detector parity with Python implementations.

Verifies that YAML-backed detectors (MCP_ENDPOINT, AUTH_CONNECTION, OPAQUE_BLOB)
produce identical FindingCandidate outputs to their Python counterparts for all
test inputs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.config import RazinConfig, load_config
from razin.detectors.docs.rules import (
    AuthConnectionDetector,
    McpEndpointDetector,
)
from razin.detectors.rules import OpaqueBlobDetector
from razin.detectors.yaml_rules.engine import YamlDetector
from razin.detectors.yaml_rules.loader import load_yaml_detectors as load_yamls
from razin.detectors.yaml_rules.schema import validate_yaml_rule
from razin.exceptions import ConfigError
from razin.model import FindingCandidate
from razin.parsers import parse_skill_markdown_file
from razin.scanner.discovery import derive_skill_name


def _skill_file(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "SKILL.md"
    f.write_text(content, encoding="utf-8")
    return f


def _compare_findings(
    python_findings: list[FindingCandidate],
    yaml_findings: list[FindingCandidate],
) -> None:
    """Assert YAML findings match Python findings on all significant fields."""
    assert len(yaml_findings) == len(
        python_findings
    ), f"Count mismatch: YAML={len(yaml_findings)}, Python={len(python_findings)}"

    for py_f, yaml_f in zip(
        sorted(python_findings, key=lambda f: (f.rule_id, f.evidence.path, f.evidence.line or 0)),
        sorted(yaml_findings, key=lambda f: (f.rule_id, f.evidence.path, f.evidence.line or 0)),
        strict=True,
    ):
        assert yaml_f.rule_id == py_f.rule_id
        assert yaml_f.score == py_f.score
        assert yaml_f.confidence == py_f.confidence
        assert yaml_f.title == py_f.title
        assert yaml_f.evidence.path == py_f.evidence.path
        assert yaml_f.evidence.line == py_f.evidence.line
        assert yaml_f.recommendation == py_f.recommendation


def _get_yaml_detector(rule_id: str) -> YamlDetector:
    """Load the YAML detector for a given rule_id."""
    detectors = load_yamls(rule_ids=frozenset({rule_id}))
    assert len(detectors) == 1, f"Expected 1 detector for {rule_id}, got {len(detectors)}"
    return detectors[0]


def test_mcp_endpoint_parity_risky_fixture(basic_repo_root: Path) -> None:
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    parsed = parse_skill_markdown_file(risky)
    skill_name = derive_skill_name(risky, basic_repo_root)

    py_det = McpEndpointDetector()
    yaml_det = _get_yaml_detector("MCP_ENDPOINT")

    py_findings = py_det.run(skill_name=skill_name, parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name=skill_name, parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)


def test_mcp_endpoint_parity_benign_fixture(basic_repo_root: Path) -> None:
    benign = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    parsed = parse_skill_markdown_file(benign)
    skill_name = derive_skill_name(benign, basic_repo_root)

    py_det = McpEndpointDetector()
    yaml_det = _get_yaml_detector("MCP_ENDPOINT")

    py_findings = py_det.run(skill_name=skill_name, parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name=skill_name, parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_mcp_endpoint_parity_mcp_url_triggers(tmp_path: Path) -> None:
    content = """---
name: mcp-test
---
# MCP Test

endpoint: https://unknown-server.io/mcp
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = McpEndpointDetector()
    yaml_det = _get_yaml_detector("MCP_ENDPOINT")

    py_findings = py_det.run(skill_name="mcp-test", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="mcp-test", parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)
    assert len(py_findings) > 0


def test_mcp_endpoint_parity_allowlisted_mcp_no_finding(tmp_path: Path) -> None:
    content = """---
name: mcp-allow
---
# MCP Allow

endpoint: https://rube.app/mcp
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig(mcp_allowlist_domains=("rube.app",))

    py_det = McpEndpointDetector()
    yaml_det = _get_yaml_detector("MCP_ENDPOINT")

    py_findings = py_det.run(skill_name="mcp-allow", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="mcp-allow", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_auth_connection_parity_risky_fixture(basic_repo_root: Path) -> None:
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    parsed = parse_skill_markdown_file(risky)
    skill_name = derive_skill_name(risky, basic_repo_root)

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name=skill_name, parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name=skill_name, parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)


def test_auth_connection_parity_benign_fixture(basic_repo_root: Path) -> None:
    benign = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    parsed = parse_skill_markdown_file(benign)
    skill_name = derive_skill_name(benign, basic_repo_root)

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name=skill_name, parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name=skill_name, parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_auth_connection_parity_auth_with_strong_and_weak_hints(tmp_path: Path) -> None:
    content = """---
name: auth-test
---
# Auth Test

You must authenticate with OAuth to proceed.
Provide your API key for connection setup.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="auth-test", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="auth-test", parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)
    assert len(py_findings) > 0


def test_auth_connection_parity_no_strong_hints_no_finding(tmp_path: Path) -> None:
    content = """---
name: weak-only
---
# Weak Only

Use your API key and token for pagination.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="weak-only", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="weak-only", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_auth_connection_parity_negated_auth_no_finding(tmp_path: Path) -> None:
    content = """---
name: negated
---
# Negated Auth

No authentication required for this skill.
No need for API key or token.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="negated", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="negated", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_auth_connection_parity_auth_link_pattern(tmp_path: Path) -> None:
    """Parity: 'auth link' (strong) + 'connection' (weak) fires in both engines."""
    content = """---
name: rube-test
---
# Rube MCP

Follow the returned auth link to complete connection setup.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="rube-test", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="rube-test", parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)
    assert len(py_findings) > 0


def test_auth_connection_parity_authorization_hint(tmp_path: Path) -> None:
    """Parity: 'authorization' (strong) + 'api key' (weak) fires in both engines."""
    content = """---
name: authz-test
---
# AuthZ

Complete the authorization flow and provide your api key.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="authz-test", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="authz-test", parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)
    assert len(py_findings) > 0


def test_auth_connection_parity_manage_connections_tool(tmp_path: Path) -> None:
    """Parity: 'oauth' (strong) + 'RUBE_MANAGE_CONNECTIONS' (weak) fires in both engines."""
    content = """---
name: rube-oauth
---
# Rube OAuth

Set up oauth and call RUBE_MANAGE_CONNECTIONS to link account.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="rube-oauth", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="rube-oauth", parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)
    assert len(py_findings) > 0


def test_auth_connection_parity_weak_only_credentials(tmp_path: Path) -> None:
    """Parity: 'credentials' + 'connection' (both weak) produce no finding in either engine."""
    content = """---
name: weak-cred
---
# Weak Cred

Set up credentials and connection to the service.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="weak-cred", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="weak-cred", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_auth_connection_parity_negated_authorization(tmp_path: Path) -> None:
    """Parity: 'no authorization required' is negated; no finding in either engine."""
    content = """---
name: neg-authz
---
# Negated

No authorization required. Just set up the connection.
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = AuthConnectionDetector()
    yaml_det = _get_yaml_detector("AUTH_CONNECTION")

    py_findings = py_det.run(skill_name="neg-authz", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="neg-authz", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_opaque_blob_parity_risky_fixture(basic_repo_root: Path) -> None:
    risky = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    parsed = parse_skill_markdown_file(risky)
    skill_name = derive_skill_name(risky, basic_repo_root)

    py_det = OpaqueBlobDetector()
    yaml_det = _get_yaml_detector("OPAQUE_BLOB")

    py_findings = py_det.run(skill_name=skill_name, parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name=skill_name, parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)


def test_opaque_blob_parity_benign_fixture(basic_repo_root: Path) -> None:
    benign = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    parsed = parse_skill_markdown_file(benign)
    skill_name = derive_skill_name(benign, basic_repo_root)

    py_det = OpaqueBlobDetector()
    yaml_det = _get_yaml_detector("OPAQUE_BLOB")

    py_findings = py_det.run(skill_name=skill_name, parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name=skill_name, parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_opaque_blob_parity_high_entropy_blob(tmp_path: Path) -> None:
    # Use the same base64-like blob from the risky fixture (80+ chars, high entropy).
    blob = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
    content = f"""---
name: blob-test
---
# Blob Test

{blob}
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = OpaqueBlobDetector()
    yaml_det = _get_yaml_detector("OPAQUE_BLOB")

    py_findings = py_det.run(skill_name="blob-test", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="blob-test", parsed=parsed, config=config)

    _compare_findings(py_findings, yaml_findings)
    assert len(py_findings) > 0


def test_opaque_blob_parity_short_value_no_finding(tmp_path: Path) -> None:
    content = """---
name: short-val
---
# Short

data: abc123
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = OpaqueBlobDetector()
    yaml_det = _get_yaml_detector("OPAQUE_BLOB")

    py_findings = py_det.run(skill_name="short-val", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="short-val", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_opaque_blob_parity_prose_excluded(tmp_path: Path) -> None:
    # Long prose that has spaces and multiple words — not a blob.
    prose = "This is a very long description that explains something " * 5
    content = f"""---
name: prose-test
---
# Prose

note: {prose}
"""
    path = _skill_file(tmp_path, content)
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()

    py_det = OpaqueBlobDetector()
    yaml_det = _get_yaml_detector("OPAQUE_BLOB")

    py_findings = py_det.run(skill_name="prose-test", parsed=parsed, config=config)
    yaml_findings = yaml_det.run(skill_name="prose-test", parsed=parsed, config=config)

    assert py_findings == []
    assert yaml_findings == []


def test_yaml_schema_missing_rule_id() -> None:
    data = {"version": 1, "metadata": {}, "scoring": {}, "match": {}}
    with pytest.raises(ConfigError, match="missing required key 'rule_id'"):
        validate_yaml_rule(data, "test.yaml")


def test_yaml_schema_unknown_keys_rejected() -> None:
    data = {
        "rule_id": "TEST",
        "version": 1,
        "metadata": {
            "title": "t",
            "description": "d",
            "recommendation": "r",
            "confidence": "low",
        },
        "scoring": {"base_score": 50},
        "match": {"source": "fields", "strategy": "entropy_check", "min_length": 10, "min_entropy": 3.0},
        "dedupe": True,
        "unknown_key": "bad",
    }
    with pytest.raises(ConfigError, match="unknown keys"):
        validate_yaml_rule(data, "test.yaml")


def test_yaml_schema_invalid_confidence() -> None:
    data = {
        "rule_id": "TEST",
        "version": 1,
        "metadata": {
            "title": "t",
            "description": "d",
            "recommendation": "r",
            "confidence": "very_high",
        },
        "scoring": {"base_score": 50},
        "match": {"source": "fields", "strategy": "entropy_check", "min_length": 10, "min_entropy": 3.0},
    }
    with pytest.raises(ConfigError, match="confidence"):
        validate_yaml_rule(data, "test.yaml")


def test_yaml_schema_score_out_of_range() -> None:
    data = {
        "rule_id": "TEST",
        "version": 1,
        "metadata": {
            "title": "t",
            "description": "d",
            "recommendation": "r",
            "confidence": "low",
        },
        "scoring": {"base_score": 150},
        "match": {"source": "fields", "strategy": "entropy_check", "min_length": 10, "min_entropy": 3.0},
    }
    with pytest.raises(ConfigError, match="base_score must be int 0-100"):
        validate_yaml_rule(data, "test.yaml")


def test_yaml_schema_invalid_strategy() -> None:
    data = {
        "rule_id": "TEST",
        "version": 1,
        "metadata": {
            "title": "t",
            "description": "d",
            "recommendation": "r",
            "confidence": "low",
        },
        "scoring": {"base_score": 50},
        "match": {"source": "fields", "strategy": "nonexistent"},
    }
    with pytest.raises(ConfigError, match="match.strategy"):
        validate_yaml_rule(data, "test.yaml")


def test_yaml_schema_valid_rule_passes() -> None:
    data = {
        "rule_id": "VALID",
        "version": 1,
        "metadata": {
            "title": "Valid Rule",
            "description": "A valid YAML rule.",
            "recommendation": "Nothing to do.",
            "confidence": "high",
        },
        "scoring": {"base_score": 50},
        "match": {
            "source": "fields",
            "strategy": "entropy_check",
            "min_length": 80,
            "min_entropy": 4.5,
        },
        "dedupe": True,
    }
    validate_yaml_rule(data, "test.yaml")


def test_yaml_loader_loads_all_three_prototypes() -> None:
    detectors = load_yamls()
    rule_ids = {d.detector_id for d in detectors}
    assert rule_ids == {"AUTH_CONNECTION", "MCP_ENDPOINT", "OPAQUE_BLOB"}


def test_yaml_loader_filter_by_rule_id() -> None:
    detectors = load_yamls(rule_ids=frozenset({"MCP_ENDPOINT"}))
    assert len(detectors) == 1
    assert detectors[0].detector_id == "MCP_ENDPOINT"


def test_yaml_loader_empty_filter_returns_nothing() -> None:
    detectors = load_yamls(rule_ids=frozenset())
    assert detectors == []


def test_yaml_loader_nonexistent_dir_returns_empty(tmp_path: Path) -> None:
    detectors = load_yamls(rules_dir=tmp_path / "nonexistent")
    assert detectors == []


def test_yaml_loader_yaml_detector_exposes_version() -> None:
    detectors = load_yamls(rule_ids=frozenset({"MCP_ENDPOINT"}))
    assert detectors[0].version == 1


def test_yaml_loader_yaml_detector_exposes_source_yaml() -> None:
    detectors = load_yamls(rule_ids=frozenset({"OPAQUE_BLOB"}))
    source = detectors[0].source_yaml
    assert source["rule_id"] == "OPAQUE_BLOB"
    assert source["version"] == 1
