"""Shared output-filter helpers for reporters and file writers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from razin.constants.scoring import SEVERITY_RANK
from razin.model import Finding
from razin.types import Severity


@dataclass(frozen=True)
class OutputFilters:
    """Display/output filters that do not affect scan execution."""

    min_severity: Severity | None = None
    security_only: bool = False

    def active(self) -> bool:
        """Whether any filter is enabled."""
        return self.min_severity is not None or self.security_only


def finding_passes_filters(finding: Finding, filters: OutputFilters) -> bool:
    """Return whether a finding should be shown under the configured filters."""
    if filters.min_severity is not None:
        threshold = SEVERITY_RANK[filters.min_severity]
        if SEVERITY_RANK[finding.severity] < threshold:
            return False
    return not (filters.security_only and finding.classification != "security")


def filter_findings(findings: Sequence[Finding], filters: OutputFilters) -> list[Finding]:
    """Return findings that pass all configured output filters."""
    return [finding for finding in findings if finding_passes_filters(finding, filters)]


def count_filtered_reasons(findings: Sequence[Finding], filters: OutputFilters) -> dict[str, int]:
    """Count findings hidden by each filter reason.

    Counts are non-overlapping: severity filtering is applied first, then
    informational classification filtering.
    """
    counts = {
        "below_min_severity": 0,
        "informational": 0,
    }
    for finding in findings:
        if filters.min_severity is not None:
            threshold = SEVERITY_RANK[filters.min_severity]
            if SEVERITY_RANK[finding.severity] < threshold:
                counts["below_min_severity"] += 1
                continue
        if filters.security_only and finding.classification != "security":
            counts["informational"] += 1
    return counts


def build_filter_metadata(
    *,
    total: int,
    shown: int,
    filters: OutputFilters,
) -> dict[str, object] | None:
    """Build stable filter metadata for JSON/SARIF payloads."""
    if not filters.active():
        return None
    filtered = max(0, total - shown)
    return {
        "min_severity": filters.min_severity,
        "security_only": filters.security_only,
        "shown": shown,
        "total": total,
        "filtered": filtered,
    }
