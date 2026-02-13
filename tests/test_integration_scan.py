"""Integration tests for full scan flow and output determinism."""

import json
from pathlib import Path

from razin.parsers import parse_skill_markdown_file
from razin.scanner import scan_workspace
from razin.scanner.discovery import derive_skill_name


def test_scan_writes_reports_and_is_deterministic(tmp_path: Path, basic_repo_root: Path) -> None:
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
    assert first_summary_payload["counts_by_severity"]["high"] >= 1

    second = scan_workspace(root=basic_repo_root, out=out_root)
    assert second.cache_hits >= 1

    second_findings_payload = json.loads(risky_findings.read_text(encoding="utf-8"))
    second_summary_payload = json.loads(risky_summary.read_text(encoding="utf-8"))

    assert first_findings_payload == second_findings_payload
    assert first_summary_payload == second_summary_payload
    assert first_summary_payload["overall_severity"] in {"medium", "high"}


def test_scan_applies_mcp_allowlist_cli_override(tmp_path: Path, basic_repo_root: Path) -> None:
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
