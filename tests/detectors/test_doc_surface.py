"""Tests for doc-surface detectors: MCP, AUTH, TOOL_INVOCATION, DYNAMIC_SCHEMA, TYPOSQUAT."""

from __future__ import annotations

from pathlib import Path

from razin.config import RazinConfig
from razin.detectors.docs.rules import (
    AuthConnectionDetector,
    DynamicSchemaDetector,
    McpDenylistDetector,
    McpEndpointDetector,
    McpRequiredDetector,
    ToolInvocationDetector,
)
from razin.detectors.rules import TyposquatDetector
from razin.parsers import parse_skill_markdown_file

from .conftest import _skill_file


def test_typosquat_ignores_short_names(tmp_path: Path) -> None:
    """Typosquat ignores short skill names."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: abc\n---\n# Title\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = TyposquatDetector()
    config = RazinConfig(typosquat_baseline=("abd",))

    findings = detector.run(skill_name="abc", parsed=parsed, config=config)

    assert findings == []


def test_mcp_required_detector_finds_frontmatter_requirement(basic_repo_root: Path) -> None:
    """MCP_REQUIRED fires when requires.mcp is in frontmatter."""
    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky_file)
    detector = McpRequiredDetector()

    findings = detector.run(skill_name="risky", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].rule_id == "MCP_REQUIRED"


def test_mcp_endpoint_detector_respects_allowlist(tmp_path: Path) -> None:
    """MCP_ENDPOINT respects allowlist to suppress known-safe endpoints."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: endpoint-check\n---\n" "Use https://rube.app/mcp and https://evil.example.net/mcp\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = McpEndpointDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(mcp_allowlist_domains=("rube.app",)),
    )

    assert findings
    assert all("rube.app/mcp" not in finding.description for finding in findings)
    assert any("evil.example.net/mcp" in finding.description for finding in findings)


def test_mcp_denylist_detector_finds_blocked_endpoint(tmp_path: Path) -> None:
    """MCP_DENYLIST fires on denylisted endpoint domains."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: denylist-check\n---\n" "Endpoint: https://blocked.example.com/mcp\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = McpDenylistDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(mcp_denylist_domains=("blocked.example.com",)),
    )

    assert findings
    assert findings[0].rule_id == "MCP_DENYLIST"


def test_mcp_denylist_detector_wildcard_blocks_all_mcp_endpoints(tmp_path: Path) -> None:
    """MCP_DENYLIST with wildcard (*) blocks all MCP endpoints."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: wildcard-denylist\n---\n" "Endpoint: https://any.example.com/mcp\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = McpDenylistDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(mcp_denylist_domains=("*",)),
    )

    assert findings
    assert findings[0].rule_id == "MCP_DENYLIST"


def test_tool_invocation_detector_honors_prefixes(tmp_path: Path) -> None:
    """Consolidated finding includes prefix-matched tokens."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: tool-check\n---\n" "Use RUBE_SEARCH and MCP_LIST_TOOLS and SOMETHING_ELSE.\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = ToolInvocationDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(tool_prefixes=("RUBE_", "MCP_")),
    )

    assert len(findings) == 1
    assert "2 tool invocation tokens" in findings[0].description
    assert "RUBE_SEARCH" in findings[0].evidence.snippet
    assert "MCP_LIST_TOOLS" in findings[0].evidence.snippet
    assert "SOMETHING_ELSE" not in findings[0].evidence.snippet


def test_tool_invocation_detector_detects_service_tokens(tmp_path: Path) -> None:
    """Service tokens are consolidated into a single finding."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: tool-check\n---\n" "Use SLACK_SEND_MESSAGE and STRIPE_CREATE_CHARGE and USE_THIS_FORMAT.\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = ToolInvocationDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(tool_prefixes=("RUBE_", "MCP_")),
    )

    assert len(findings) == 1
    assert "SLACK_SEND_MESSAGE" in findings[0].evidence.snippet
    assert "STRIPE_CREATE_CHARGE" in findings[0].evidence.snippet


def test_dynamic_schema_detector_is_low_confidence(tmp_path: Path) -> None:
    """DYNAMIC_SCHEMA produces low-confidence findings."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: schema-check\n---\n" "Before executing any tool, list tools and inspect schema first.\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = DynamicSchemaDetector()

    findings = detector.run(skill_name="sample", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].confidence == "low"
    assert findings[0].rule_id == "DYNAMIC_SCHEMA"


def test_auth_connection_detector_needs_multiple_hints(tmp_path: Path) -> None:
    """AUTH_CONNECTION requires 2+ non-negated hints to fire."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: auth-check\n---\n" "Authenticate with API key and complete connection setup.\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = AuthConnectionDetector()

    findings = detector.run(skill_name="sample", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_backtick_mcp_url_detected(tmp_path: Path) -> None:
    """Backtick-wrapped MCP URL is detected by MCP_ENDPOINT."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Add `https://evil.example.net/mcp` as an MCP server.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = McpEndpointDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "MCP_ENDPOINT"
    assert "evil.example.net/mcp" in findings[0].description


def test_paren_mcp_url_detected(tmp_path: Path) -> None:
    """Markdown-link wrapped MCP URL is detected by MCP_ENDPOINT."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "See [MCP](https://evil.example.net/mcp) for details.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = McpEndpointDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "MCP_ENDPOINT"


def test_negated_no_api_keys_skipped(tmp_path: Path) -> None:
    """'No API keys needed' with no other auth hints does not fire."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "No API keys needed -- just add the endpoint and it works.\n"
        "No token or secret required.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_affirmative_auth_still_fires(tmp_path: Path) -> None:
    """Genuine auth requirements trigger AUTH_CONNECTION."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Authenticate with API key and complete connection setup.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_mixed_negated_and_affirmative(tmp_path: Path) -> None:
    """If at least 2 non-negated hints remain after negation filtering, still fires."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "No API keys needed for basic access.\n"
        "But you must authenticate with OAuth and complete the connection.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_weak_hints_only_does_not_fire(tmp_path: Path) -> None:
    """'token' + 'connect' (both weak) should no longer trigger."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "Check responses for pagination tokens and continue fetching until complete.\n"
        "Rube MCP must be connected.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_strong_plus_weak_fires(tmp_path: Path) -> None:
    """'authenticate' (strong) + 'connection' (weak) should fire."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "You must authenticate before using the connection.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_two_strong_hints_fires(tmp_path: Path) -> None:
    """Two strong hints ('oauth' + 'login') should fire."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Complete OAuth login to proceed.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings


def test_evidence_points_to_strong_hint_line(tmp_path: Path) -> None:
    """Evidence references the line with the strong auth hint."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Pagination uses token cursors.\n" "You must authenticate with OAuth to proceed.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert "authenticate" in findings[0].evidence.snippet.lower()
