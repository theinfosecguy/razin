"""Tests for MCP remote endpoint evaluation helpers."""

from __future__ import annotations

from pathlib import Path

from razin.config import RazinConfig
from razin.model import DocumentField, DocumentKey, Evidence, FindingCandidate, ParsedSkillDocument
from razin.scanner.mcp_remote import (
    collect_mcp_remote_candidates,
    parse_referenced_mcp_endpoints,
    resolve_associated_mcp_json,
    suppress_mcp_remote_candidates,
)


def _parsed_skill(tmp_path: Path, *, frontmatter: dict[str, object] | None) -> ParsedSkillDocument:
    """Create a minimal parsed skill document fixture for MCP tests."""
    skill_path = tmp_path / "skills" / "demo" / "SKILL.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_path.write_text("# Demo\n", encoding="utf-8")
    return ParsedSkillDocument(
        file_path=skill_path,
        raw_text="# Demo\n",
        frontmatter=frontmatter,
        body="# Demo",
        fields=(DocumentField(path=("line", "1"), value="# Demo", line=1, snippet="# Demo"),),
        keys=(DocumentKey(path=("line", "1"), key="title", line=1, snippet="# Demo"),),
    )


def test_resolve_associated_mcp_json_prefers_nearest_ancestor(tmp_path: Path) -> None:
    """Nearest ancestor `.mcp.json` should win over root fallback."""
    root = tmp_path / "repo"
    skill_dir = root / "skills" / "nested" / "alpha"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text("# skill\n", encoding="utf-8")

    (root / ".mcp.json").write_text("{}", encoding="utf-8")
    nearest = root / "skills" / ".mcp.json"
    nearest.write_text("{}", encoding="utf-8")

    resolved = resolve_associated_mcp_json(skill_file, root)

    assert resolved == nearest


def test_parse_referenced_mcp_endpoints_classifies_public_ip(tmp_path: Path) -> None:
    """Referenced server URL with public IP should be parsed and classified."""
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text(
        '{\n  "mcpServers": {\n    "remote": {"url": "http://8.8.8.8/mcp"}\n  }\n}\n',
        encoding="utf-8",
    )

    endpoints = parse_referenced_mcp_endpoints(mcp_json, ("remote",))

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.scheme == "http"
    assert endpoint.host == "8.8.8.8"
    assert endpoint.is_ip is True
    assert endpoint.is_public_ip is True


def test_parse_referenced_mcp_endpoints_skips_command_only_server(tmp_path: Path) -> None:
    """Command-only referenced servers should be ignored by remote URL checks."""
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text(
        '{\n  "mcpServers": {\n    "local": {"command": "npx", "args": ["-y", "tool"]}\n  }\n}\n',
        encoding="utf-8",
    )

    endpoints = parse_referenced_mcp_endpoints(mcp_json, ("local",))

    assert endpoints == []


def test_suppress_mcp_remote_candidates_keeps_highest_priority() -> None:
    """Suppression should keep only the highest-priority MCP remote rule."""
    base = FindingCandidate(
        rule_id="MCP_REMOTE_NON_HTTPS",
        score=52,
        confidence="high",
        title="t",
        description="d",
        evidence=Evidence(path="x", line=1, snippet="x"),
        recommendation="r",
    )
    mid = FindingCandidate(
        rule_id="MCP_REMOTE_RAW_IP",
        score=82,
        confidence="high",
        title="t",
        description="d",
        evidence=Evidence(path="x", line=1, snippet="x"),
        recommendation="r",
    )
    top = FindingCandidate(
        rule_id="MCP_REMOTE_DENYLIST",
        score=90,
        confidence="high",
        title="t",
        description="d",
        evidence=Evidence(path="x", line=1, snippet="x"),
        recommendation="r",
    )

    suppressed = suppress_mcp_remote_candidates(
        [
            ("http://8.8.8.8/mcp", base),
            ("http://8.8.8.8/mcp", mid),
            ("http://8.8.8.8/mcp", top),
        ]
    )

    assert len(suppressed) == 1
    assert suppressed[0].rule_id == "MCP_REMOTE_DENYLIST"


def test_collect_mcp_remote_candidates_applies_gating_and_localhost_exception(tmp_path: Path) -> None:
    """Localhost HTTP should be excluded while denylisted remote endpoint remains."""
    root = tmp_path / "repo"
    skill_dir = root / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / ".mcp.json").write_text(
        (
            '{\n  "mcpServers": {\n'
            '    "local": {"url": "http://localhost/mcp"},\n'
            '    "remote": {"url": "http://8.8.8.8/mcp"}\n'
            "  }\n}\n"
        ),
        encoding="utf-8",
    )

    parsed = _parsed_skill(
        root,
        frontmatter={
            "requires": {
                "mcp": ["local", "remote"],
            }
        },
    )

    candidates, warnings = collect_mcp_remote_candidates(
        parsed=parsed,
        root=root,
        config=RazinConfig(mcp_denylist_domains=("8.8.8.8",)),
    )

    rule_ids = {candidate.rule_id for candidate in candidates}

    assert warnings == []
    assert "MCP_REMOTE_NON_HTTPS" not in rule_ids
    assert "MCP_REMOTE_DENYLIST" in rule_ids
