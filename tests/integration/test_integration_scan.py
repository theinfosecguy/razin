"""Integration tests for full scan flow and output determinism."""

import json
from pathlib import Path

from razin.parsers import parse_skill_markdown_file
from razin.scanner import scan_workspace
from razin.scanner.discovery import derive_skill_name


def test_scan_writes_reports_and_is_deterministic(tmp_path: Path, basic_repo_root: Path) -> None:
    """Repeated scans over same fixture should produce stable outputs and cache hits."""
    out_root = tmp_path / "output"

    first = scan_workspace(root=basic_repo_root, out=out_root)
    assert first.scanned_files >= 3
    assert first.total_findings >= 1

    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky_file)
    declared_name = None
    if isinstance(parsed.frontmatter, dict):
        name_value = parsed.frontmatter.get("name")
        if isinstance(name_value, str) and name_value.strip():
            declared_name = name_value.strip()
    risky_skill_name = derive_skill_name(
        risky_file,
        basic_repo_root,
        declared_name=declared_name,
    )
    risky_findings = out_root / risky_skill_name / "findings.json"
    risky_summary = out_root / risky_skill_name / "summary.json"

    assert risky_findings.is_file()
    assert risky_summary.is_file()

    first_findings_payload = json.loads(risky_findings.read_text(encoding="utf-8"))
    first_summary_payload = json.loads(risky_summary.read_text(encoding="utf-8"))

    observed_rules = {finding["rule_id"] for finding in first_findings_payload}
    finding_ids = [finding["id"] for finding in first_findings_payload]
    assert {
        "NET_RAW_IP",
        "SECRET_REF",
        "EXEC_FIELDS",
        "OPAQUE_BLOB",
        "TYPOSQUAT",
        "MCP_REQUIRED",
        "MCP_ENDPOINT",
        "TOOL_INVOCATION",
        "DYNAMIC_SCHEMA",
        "AUTH_CONNECTION",
    }.issubset(observed_rules)
    assert len(finding_ids) == len(set(finding_ids))
    assert first_summary_payload["finding_count"] >= 1

    second = scan_workspace(root=basic_repo_root, out=out_root)
    assert second.cache_hits >= 1

    second_findings_payload = json.loads(risky_findings.read_text(encoding="utf-8"))
    second_summary_payload = json.loads(risky_summary.read_text(encoding="utf-8"))

    assert first_findings_payload == second_findings_payload
    assert first_summary_payload == second_summary_payload
    assert first_summary_payload["overall_severity"] in {"medium", "high"}


def test_scan_applies_mcp_allowlist_cli_override(tmp_path: Path, basic_repo_root: Path) -> None:
    """CLI MCP allowlist override should suppress matching MCP endpoint findings."""
    out_root = tmp_path / "output"
    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"

    parsed = parse_skill_markdown_file(risky_file)
    declared_name = None
    if isinstance(parsed.frontmatter, dict):
        name_value = parsed.frontmatter.get("name")
        if isinstance(name_value, str) and name_value.strip():
            declared_name = name_value.strip()

    risky_skill_name = derive_skill_name(
        risky_file,
        basic_repo_root,
        declared_name=declared_name,
    )

    scan_workspace(
        root=basic_repo_root,
        out=out_root,
        mcp_allowlist=("evil.example.net",),
    )

    findings_payload = json.loads((out_root / risky_skill_name / "findings.json").read_text(encoding="utf-8"))
    rule_ids = {finding["rule_id"] for finding in findings_payload}

    assert "MCP_ENDPOINT" not in rule_ids


def test_scan_suppresses_unknown_domain_when_mcp_endpoint_covers_same_line(tmp_path: Path) -> None:
    """Overlapping MCP endpoint evidence should suppress NET_UNKNOWN_DOMAIN noise."""
    skill_dir = tmp_path / "skills" / "mcp"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: mcp-overlap\n---\nUse https://rube.app/mcp in this skill.\n",
        encoding="utf-8",
    )

    result = scan_workspace(root=tmp_path)
    rule_ids = [finding.rule_id for finding in result.findings]

    assert "MCP_ENDPOINT" in rule_ids
    assert "NET_UNKNOWN_DOMAIN" not in rule_ids


def _write_mcp_skill_repo(
    tmp_path: Path,
    *,
    requires_mcp: str,
    mcp_json_text: str | None,
) -> Path:
    """Create a minimal repo fixture with one MCP-linked skill and optional `.mcp.json`."""
    root = tmp_path / "repo"
    skill_dir = root / "skills" / "mcp"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "\n".join(
            [
                "---",
                "name: mcp-json-skill",
                "requires:",
                f"  mcp: [{requires_mcp}]",
                "---",
                "# MCP test",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    if mcp_json_text is not None:
        (skill_dir / ".mcp.json").write_text(mcp_json_text, encoding="utf-8")
    return root


def test_mcp_remote_https_domain_produces_no_remote_finding(tmp_path: Path) -> None:
    """Referenced HTTPS domain endpoint should not trigger MCP remote findings."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="safe",
        mcp_json_text='{"mcpServers": {"safe": {"url": "https://safe.example.com/mcp"}}}\n',
    )

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_NON_HTTPS" not in rule_ids
    assert "MCP_REMOTE_RAW_IP" not in rule_ids
    assert "MCP_REMOTE_DENYLIST" not in rule_ids


def test_mcp_remote_http_endpoint_emits_non_https(tmp_path: Path) -> None:
    """Referenced HTTP endpoint should trigger MCP_REMOTE_NON_HTTPS."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="plain",
        mcp_json_text='{"mcpServers": {"plain": {"url": "http://evil.example.net/mcp"}}}\n',
    )

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_NON_HTTPS" in rule_ids


def test_mcp_remote_public_raw_ip_emits_raw_ip(tmp_path: Path) -> None:
    """Referenced public raw IP endpoint should trigger MCP_REMOTE_RAW_IP."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="ipbox",
        mcp_json_text='{"mcpServers": {"ipbox": {"url": "https://8.8.8.8/mcp"}}}\n',
    )

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_RAW_IP" in rule_ids


def test_mcp_remote_denylist_suppresses_lower_priority_for_same_endpoint(tmp_path: Path) -> None:
    """Denylist match should suppress lower-priority MCP remote findings per endpoint."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="blocked",
        mcp_json_text='{"mcpServers": {"blocked": {"url": "http://8.8.8.8/mcp"}}}\n',
    )
    (root / "razin.yaml").write_text("mcp_denylist_domains:\n  - 8.8.8.8\n", encoding="utf-8")

    result = scan_workspace(root=root)
    matches = [finding for finding in result.findings if finding.rule_id.startswith("MCP_REMOTE_")]
    ids = {finding.rule_id for finding in matches}

    assert ids == {"MCP_REMOTE_DENYLIST"}


def test_mcp_remote_rules_ignore_unreferenced_servers(tmp_path: Path) -> None:
    """Only servers referenced by requires.mcp should be evaluated for remote rules."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="safe",
        mcp_json_text=(
            '{"mcpServers": {'
            '"safe": {"url": "https://safe.example.com/mcp"}, '
            '"other": {"url": "http://8.8.8.8/mcp"}'
            '}}\n'
        ),
    )
    (root / "razin.yaml").write_text("mcp_denylist_domains:\n  - 8.8.8.8\n", encoding="utf-8")

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_NON_HTTPS" not in rule_ids
    assert "MCP_REMOTE_RAW_IP" not in rule_ids
    assert "MCP_REMOTE_DENYLIST" not in rule_ids


def test_mcp_remote_rules_skip_when_requires_mcp_missing(tmp_path: Path) -> None:
    """Missing requires.mcp should disable all MCP remote rules."""
    root = tmp_path / "repo"
    skill_dir = root / "skills" / "no-mcp"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: no-mcp\n---\n# no mcp\n", encoding="utf-8")
    (skill_dir / ".mcp.json").write_text(
        '{"mcpServers": {"server": {"url": "http://8.8.8.8/mcp"}}}\n',
        encoding="utf-8",
    )

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_NON_HTTPS" not in rule_ids
    assert "MCP_REMOTE_RAW_IP" not in rule_ids
    assert "MCP_REMOTE_DENYLIST" not in rule_ids


def test_mcp_remote_rules_skip_when_mcp_json_missing(tmp_path: Path) -> None:
    """Missing associated `.mcp.json` should disable MCP remote checks."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="missing",
        mcp_json_text=None,
    )

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_NON_HTTPS" not in rule_ids
    assert "MCP_REMOTE_RAW_IP" not in rule_ids
    assert "MCP_REMOTE_DENYLIST" not in rule_ids


def test_mcp_remote_rules_skip_referenced_command_only_server(tmp_path: Path) -> None:
    """Referenced command-only servers should not produce remote MCP findings."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="local",
        mcp_json_text='{"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}\n',
    )

    result = scan_workspace(root=root)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "MCP_REMOTE_NON_HTTPS" not in rule_ids
    assert "MCP_REMOTE_RAW_IP" not in rule_ids
    assert "MCP_REMOTE_DENYLIST" not in rule_ids


def test_mcp_remote_cache_invalidates_when_mcp_json_changes(tmp_path: Path) -> None:
    """Cache should invalidate skill results when associated `.mcp.json` content changes."""
    root = _write_mcp_skill_repo(
        tmp_path,
        requires_mcp="remote",
        mcp_json_text='{"mcpServers": {"remote": {"url": "https://safe.example.com/mcp"}}}\n',
    )
    out = tmp_path / "output"

    first = scan_workspace(root=root, out=out)
    first_rules = {finding.rule_id for finding in first.findings}
    assert "MCP_REMOTE_RAW_IP" not in first_rules

    (root / "skills" / "mcp" / ".mcp.json").write_text(
        '{"mcpServers": {"remote": {"url": "http://8.8.8.8/mcp"}}}\n',
        encoding="utf-8",
    )

    second = scan_workspace(root=root, out=out)
    second_rules = {finding.rule_id for finding in second.findings}

    assert "MCP_REMOTE_RAW_IP" in second_rules
    assert second.cache_misses >= 1
