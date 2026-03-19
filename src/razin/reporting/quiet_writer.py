"""JSONL quiet-mode output writer for CI and automation pipelines."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from razin.constants.reporting import QUIET_STREAM_VERSION, SCHEMA_VERSION
from razin.constants.scoring import SEVERITY_RANK
from razin.model import Finding, ScanResult
from razin.types.common import Severity


def write_quiet_output(
    *,
    out_path: Path,
    result: ScanResult,
    min_severity: Severity | None = None,
    security_only: bool = False,
    include_warnings: bool = True,
    include_summary: bool = True,
    write_mode: str = "overwrite",
    gate_failed: bool = False,
) -> None:
    """Write scan results to a JSONL file with finding, warning, and summary records."""
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_findings = result.findings
    written_findings = _filter_findings(all_findings, min_severity, security_only)

    if write_mode == "append":
        _write_append(
            out_path,
            written_findings,
            result.warnings if include_warnings else (),
            result,
            include_summary,
            gate_failed,
            len(all_findings),
        )
    else:
        _write_overwrite(
            out_path,
            written_findings,
            result.warnings if include_warnings else (),
            result,
            include_summary,
            gate_failed,
            len(all_findings),
        )


def _filter_findings(
    findings: tuple[Finding, ...],
    min_severity: Severity | None,
    security_only: bool,
) -> tuple[Finding, ...]:
    """Apply output filters to select which findings to write."""
    filtered: list[Finding] = list(findings)
    if security_only:
        filtered = [f for f in filtered if f.classification == "security"]
    if min_severity is not None:
        min_rank = SEVERITY_RANK.get(min_severity, 0)
        filtered = [f for f in filtered if SEVERITY_RANK.get(f.severity, 0) >= min_rank]
    return tuple(filtered)


def _write_overwrite(
    out_path: Path,
    written_findings: tuple[Finding, ...],
    warnings: tuple[str, ...],
    result: ScanResult,
    include_summary: bool,
    gate_failed: bool,
    total_count: int,
) -> None:
    """Write quiet output atomically using temp file + rename."""
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=out_path.parent,
            prefix=".quiet-tmp-",
            suffix=".jsonl",
            delete=False,
        ) as handle:
            temp_name = handle.name
            _write_records(handle, written_findings, warnings, result, include_summary, gate_failed, total_count)
    except Exception:
        if temp_name:
            with suppress(FileNotFoundError):
                Path(temp_name).unlink()
        raise

    assert temp_name is not None
    os.replace(temp_name, out_path)


def _write_append(
    out_path: Path,
    written_findings: tuple[Finding, ...],
    warnings: tuple[str, ...],
    result: ScanResult,
    include_summary: bool,
    gate_failed: bool,
    total_count: int,
) -> None:
    """Append quiet output records to an existing file."""
    with open(out_path, "a", encoding="utf-8") as handle:
        _write_records(handle, written_findings, warnings, result, include_summary, gate_failed, total_count)


def _write_records(
    handle: Any,
    written_findings: tuple[Finding, ...],
    warnings: tuple[str, ...],
    result: ScanResult,
    include_summary: bool,
    gate_failed: bool,
    total_count: int,
) -> None:
    """Write JSONL records to a file handle."""
    for finding in written_findings:
        record = _envelope("finding", finding.to_dict())
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")

    for warning_text in warnings:
        record = _envelope("warning", {"message": warning_text})
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")

    if include_summary:
        summary_data = _build_summary_data(result, len(written_findings), total_count, gate_failed)
        record = _envelope("summary", summary_data)
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")


def _envelope(record_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Wrap a data payload in the quiet stream envelope."""
    return {
        "type": record_type,
        "version": QUIET_STREAM_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": data,
    }


def _build_summary_data(
    result: ScanResult,
    written_count: int,
    total_count: int,
    gate_failed: bool,
) -> dict[str, Any]:
    """Build the summary record payload with transparency fields."""
    return {
        "schema_version": SCHEMA_VERSION,
        "scanned_files": result.scanned_files,
        "total_findings": total_count,
        "written_findings": written_count,
        "filtered_out_findings": total_count - written_count,
        "aggregate_score": result.aggregate_score,
        "aggregate_severity": result.aggregate_severity,
        "counts_by_severity": result.counts_by_severity,
        "gate_scope": "all_findings",
        "gate_failed": gate_failed,
        "duration_seconds": round(result.duration_seconds, 3),
    }
