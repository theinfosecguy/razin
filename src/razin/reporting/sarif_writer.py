"""SARIF 2.1.0 export writer for scan findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from razin import __version__
from razin.constants.reporting import (
    SARIF_FINDINGS_FILENAME,
    SARIF_SCHEMA_URI,
    SARIF_SEVERITY_MAP,
    SARIF_TOOL_NAME,
    SARIF_VERSION,
)
from razin.io import write_text_atomic
from razin.model import Finding


def _build_sarif_result(finding: Finding) -> dict[str, Any]:
    """Map a single Finding to a SARIF result object."""
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": SARIF_SEVERITY_MAP.get(finding.severity, "note"),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.evidence.path},
                },
            },
        ],
        "partialFingerprints": {"findingId": finding.id},
        "properties": {
            "score": finding.score,
            "confidence": finding.confidence,
            "skill": finding.skill,
            "recommendation": finding.recommendation,
        },
    }

    if finding.evidence.line is not None:
        result["locations"][0]["physicalLocation"]["region"] = {
            "startLine": finding.evidence.line,
        }

    return result


def _build_sarif_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Derive minimal SARIF rule descriptors from observed rule_ids."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = f

    rules: list[dict[str, Any]] = []
    for rule_id in sorted(seen):
        f = seen[rule_id]
        rules.append(
            {
                "id": rule_id,
                "shortDescription": {"text": f.title},
            }
        )
    return rules


def build_sarif_envelope(findings: list[Finding]) -> dict[str, Any]:
    """Build a complete SARIF 2.1.0 document from findings."""
    sorted_findings = sorted(findings, key=lambda f: (-f.score, f.id))

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": SARIF_TOOL_NAME,
                        "version": __version__,
                        "rules": _build_sarif_rules(sorted_findings),
                    },
                },
                "results": [_build_sarif_result(f) for f in sorted_findings],
            },
        ],
    }


def write_sarif_findings(out_root: Path, findings: list[Finding]) -> Path:
    """Write a global findings.sarif under the output root and return the path."""
    sarif_path = out_root / SARIF_FINDINGS_FILENAME

    envelope = build_sarif_envelope(findings)
    write_text_atomic(
        path=sarif_path,
        content=json.dumps(envelope, indent=2) + "\n",
        temp_prefix=".sarif_tmp_",
        temp_suffix=".sarif",
    )
    return sarif_path
