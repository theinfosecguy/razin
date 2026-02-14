"""CSV export writer for scan findings."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from razin.constants.reporting import CSV_COLUMNS, CSV_FINDINGS_FILENAME
from razin.io import write_text_atomic
from razin.model import Finding


def write_csv_findings(out_root: Path, findings: list[Finding]) -> Path:
    """Write a global findings.csv under the output root and return the path."""
    csv_path = out_root / CSV_FINDINGS_FILENAME
    content = render_csv_string(findings)
    write_text_atomic(
        path=csv_path,
        content=content,
        temp_prefix=".csv_tmp_",
        temp_suffix=".csv",
    )
    return csv_path


def render_csv_string(findings: list[Finding]) -> str:
    """Render findings as a CSV string (useful for testing)."""
    sorted_findings = sorted(findings, key=lambda f: (-f.score, f.id))

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for f in sorted_findings:
        writer.writerow(
            (
                f.id,
                f.skill,
                f.rule_id,
                f.severity,
                f.score,
                f.confidence,
                f.evidence.path,
                f.evidence.line if f.evidence.line is not None else "",
                f.title,
                f.description,
                f.recommendation,
            )
        )
    return buf.getvalue()
