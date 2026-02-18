"""Scan-output helpers for ``razin init --from-scan``."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from razin.cli.domain_analysis import extract_domain_from_finding_text, sort_domain_counts
from razin.constants.init import (
    INIT_FROM_SCAN_RULE_IDS,
    INIT_MCP_ENDPOINT_RULE_ID,
    INIT_NET_DOC_DOMAIN_RULE_ID,
)
from razin.constants.reporting import FINDINGS_FILENAME
from razin.io.json_io import load_json_file
from razin.types.init_config import InitFromScanAnalysis


def collect_domain_candidates_from_output(output_dir: Path) -> InitFromScanAnalysis:
    """Collect domain candidates from scan output ``findings.json`` files."""
    findings_paths = sorted(output_dir.rglob(FINDINGS_FILENAME))
    net_doc_counts: Counter[str] = Counter()
    mcp_endpoint_counts: Counter[str] = Counter()
    warnings: list[str] = []
    files_loaded = 0
    net_doc_findings_considered = 0
    mcp_endpoint_findings_considered = 0

    for findings_path in findings_paths:
        entries = _load_findings_entries(findings_path=findings_path, warnings=warnings)
        if entries is None:
            continue
        files_loaded += 1
        for entry in entries:
            rule_id = _safe_str(entry.get("rule_id"))
            if rule_id not in INIT_FROM_SCAN_RULE_IDS:
                continue

            description = _safe_str(entry.get("description"))
            snippet = _extract_snippet(entry.get("evidence"))
            domain = extract_domain_from_finding_text(
                rule_id=rule_id,
                description=description,
                snippet=snippet,
            )
            if not domain:
                continue
            if rule_id == INIT_NET_DOC_DOMAIN_RULE_ID:
                net_doc_findings_considered += 1
                net_doc_counts[domain] += 1
            elif rule_id == INIT_MCP_ENDPOINT_RULE_ID:
                mcp_endpoint_findings_considered += 1
                mcp_endpoint_counts[domain] += 1

    return InitFromScanAnalysis(
        allowlist_candidates=sort_domain_counts(net_doc_counts),
        mcp_allowlist_candidates=sort_domain_counts(mcp_endpoint_counts),
        warnings=tuple(warnings),
        findings_files_discovered=len(findings_paths),
        findings_files_loaded=files_loaded,
        net_doc_findings_considered=net_doc_findings_considered,
        mcp_endpoint_findings_considered=mcp_endpoint_findings_considered,
    )


def _load_findings_entries(*, findings_path: Path, warnings: list[str]) -> list[dict[str, Any]] | None:
    """Load one findings file and return normalized dictionary entries."""
    try:
        payload = load_json_file(findings_path)
    except (OSError, ValueError) as exc:
        warnings.append(f"skipping unreadable findings file {findings_path}: {exc}")
        return None

    if not isinstance(payload, list):
        warnings.append(f"skipping malformed findings file {findings_path}: expected JSON array")
        return None

    entries: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict):
            entries.append(item)
        else:
            warnings.append(f"skipping non-object finding entry in {findings_path}")
    return entries


def _safe_str(value: object) -> str:
    """Return a stripped string value or empty string."""
    if isinstance(value, str):
        return value
    return ""


def _extract_snippet(evidence_value: object) -> str:
    """Extract evidence snippet text from a serialized finding entry."""
    if isinstance(evidence_value, dict):
        return _safe_str(evidence_value.get("snippet"))
    return ""
