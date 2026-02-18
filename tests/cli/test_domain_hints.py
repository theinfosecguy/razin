"""Tests for scan-time dominant-domain hint emission."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from razin.cli.main import main
from razin.model import Evidence, Finding, ScanResult


def _make_finding(
    *,
    finding_id: str,
    rule_id: str,
    description: str,
    snippet: str,
    score: int = 15,
) -> Finding:
    """Build a minimal finding for dominant-domain hint tests."""
    return Finding(
        id=finding_id,
        severity="low",
        score=score,
        confidence="low",
        title=rule_id,
        description=description,
        evidence=Evidence(path="SKILL.md", line=1, snippet=snippet),
        skill="sample-skill",
        rule_id=rule_id,
        recommendation="Review",
    )


def _result_with_findings(findings: tuple[Finding, ...]) -> ScanResult:
    """Build a minimal scan result carrying the provided findings."""
    return ScanResult(
        scanned_files=1,
        total_findings=len(findings),
        aggregate_score=0,
        aggregate_severity="low",
        counts_by_severity={"high": 0, "medium": 0, "low": len(findings)},
        findings=findings,
        duration_seconds=0.1,
        warnings=(),
        cache_hits=0,
        cache_misses=1,
    )


@patch("razin.cli.main.scan_workspace")
def test_scan_emits_hints_for_dominant_net_doc_and_mcp(
    mock_scan: MagicMock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dominant-domain findings emit one hint per supported rule bucket."""
    findings = (
        _make_finding(
            finding_id="f1",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'composio.dev'.",
            snippet="See https://composio.dev/docs",
        ),
        _make_finding(
            finding_id="f2",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'composio.dev'.",
            snippet="See https://composio.dev/reference",
        ),
        _make_finding(
            finding_id="f3",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'other.dev'.",
            snippet="See https://other.dev/guide",
        ),
        _make_finding(
            finding_id="f4",
            rule_id="MCP_ENDPOINT",
            description="Documentation references MCP endpoint 'https://rube.app/mcp'.",
            snippet="Connect to https://rube.app/mcp",
            score=70,
        ),
        _make_finding(
            finding_id="f5",
            rule_id="MCP_ENDPOINT",
            description="Documentation references MCP endpoint 'https://rube.app/mcp'.",
            snippet="Use https://rube.app/mcp",
            score=70,
        ),
        _make_finding(
            finding_id="f6",
            rule_id="MCP_ENDPOINT",
            description="Documentation references MCP endpoint 'https://other.app/mcp'.",
            snippet="Use https://other.app/mcp",
            score=70,
        ),
    )
    mock_scan.return_value = _result_with_findings(findings)

    code = main(["scan", "--root", "."])
    captured = capsys.readouterr()
    assert code == 0
    assert (
        "hint: composio.dev appeared in 2/3 NET_DOC_DOMAIN findings; " "consider allowlist_domains in razin.yaml"
    ) in captured.err
    assert (
        "hint: rube.app appeared in 2/3 MCP_ENDPOINT findings; " "consider mcp_allowlist_domains in razin.yaml"
    ) in captured.err


@patch("razin.cli.main.scan_workspace")
def test_scan_does_not_emit_hint_for_diverse_domains(
    mock_scan: MagicMock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No hints are emitted when no domain exceeds the dominance threshold."""
    findings = (
        _make_finding(
            finding_id="f1",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'a.dev'.",
            snippet="See https://a.dev",
        ),
        _make_finding(
            finding_id="f2",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'b.dev'.",
            snippet="See https://b.dev",
        ),
        _make_finding(
            finding_id="f3",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'c.dev'.",
            snippet="See https://c.dev",
        ),
    )
    mock_scan.return_value = _result_with_findings(findings)

    code = main(["scan", "--root", "."])
    captured = capsys.readouterr()
    assert code == 0
    assert "hint:" not in captured.err


@patch("razin.cli.main.scan_workspace")
def test_scan_hints_suppressed_when_no_stdout(
    mock_scan: MagicMock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Hints are suppressed when ``--no-stdout`` is used."""
    findings = (
        _make_finding(
            finding_id="f1",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'composio.dev'.",
            snippet="See https://composio.dev/docs",
        ),
        _make_finding(
            finding_id="f2",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'composio.dev'.",
            snippet="See https://composio.dev/reference",
        ),
        _make_finding(
            finding_id="f3",
            rule_id="NET_DOC_DOMAIN",
            description="Documentation references external domain 'other.dev'.",
            snippet="See https://other.dev/guide",
        ),
    )
    mock_scan.return_value = _result_with_findings(findings)

    code = main(["scan", "--root", ".", "--no-stdout"])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    assert "hint:" not in captured.err
