"""Rich stdout reporter for scan results."""

from __future__ import annotations

import shutil
from collections import Counter

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from razin.constants.branding import ASCII_LOGO_LINES, SCAN_SUMMARY_TITLE
from razin.constants.reporting import (
    ANSI_GREEN,
    ANSI_RED,
    ANSI_RESET,
    ANSI_YELLOW,
    SEVERITY_COLORS,
)
from razin.constants.scoring import SEVERITY_RANK
from razin.model import Finding, ScanResult
from razin.reporting.filters import OutputFilters, count_filtered_reasons, filter_findings
from razin.scanner.score import aggregate_overall_score, aggregate_severity, rule_counts
from razin.types import RuleDisableSource, Severity


def _colorize(text: str, color: str) -> str:
    return f"{color}{text}{ANSI_RESET}"


def _color_severity(severity: Severity) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    return _colorize(severity, color) if color else severity


def _score_color(score: int) -> str:
    if score >= 70:
        return ANSI_RED
    if score >= 40:
        return ANSI_YELLOW
    return ANSI_GREEN


def _color_score(score: int) -> str:
    return _colorize(str(score), _score_color(score))


def _classification_short(value: str) -> str:
    return "SEC" if value == "security" else "INFO"


class StdoutReporter:
    """Formats scan results as rich, human-readable stdout output."""

    def __init__(
        self,
        result: ScanResult,
        *,
        color: bool = True,
        verbose: bool = False,
        group_by: str | None = None,
        min_severity: Severity | None = None,
        security_only: bool = False,
        summary_only: bool = False,
        fail_on: Severity | None = None,
        fail_on_score: int | None = None,
        exit_code: int = 0,
    ) -> None:
        """Initialise the reporter."""
        self._result = result
        self._color = color
        self._verbose = verbose
        self._group_by = group_by
        self._summary_only = summary_only
        self._fail_on = fail_on
        self._fail_on_score = fail_on_score
        self._exit_code = exit_code
        self._filters = OutputFilters(
            min_severity=min_severity,
            security_only=security_only,
        )
        self._shown_findings = filter_findings(result.findings, self._filters)

    def render(self) -> str:
        """Render the full stdout report as a single string."""
        sections = [self._render_header()]
        if not self._summary_only:
            sections.append(self._render_grouped_table() if self._group_by else self._render_findings_table())
        return "\n".join(section for section in sections if section)

    def _render_header(self) -> str:
        r = self._result
        sep = "  " + "─" * 38

        score_str = _color_score(r.aggregate_score) if self._color else str(r.aggregate_score)
        sev_str = _color_severity(r.aggregate_severity) if self._color else r.aggregate_severity

        skills_with_findings = len({finding.skill for finding in r.findings})
        clean_files = max(0, r.scanned_files - skills_with_findings)
        total_findings = r.total_findings
        shown_findings = len(self._shown_findings)

        lines = [
            "",
            f"  {ASCII_LOGO_LINES[0]}",
            f"  {ASCII_LOGO_LINES[1]}",
            f"  {SCAN_SUMMARY_TITLE}",
            sep,
            "",
            f"  Risk Score  {score_str} ({sev_str})",
            (
                f"  Files       {r.scanned_files} scanned / "
                f"{skills_with_findings} with findings / {clean_files} clean"
            ),
        ]

        if self._filters.active():
            filtered_summary = self._format_filtered_summary(total_findings, shown_findings)
            lines.append(f"  Findings    {shown_findings} shown / {total_findings} total ({filtered_summary})")
        else:
            lines.append(f"  Findings    {total_findings}")

        lines.append(f"  Severities  {self._format_severity_breakdown(r.counts_by_severity)}")

        if self._filters.active():
            shown_rule_counts = rule_counts(self._shown_findings)
            lines.append(f"  Top shown   {self._format_top_rules(shown_rule_counts)}")

        if r.active_rule_overrides:
            override_parts: list[str] = []
            for rule_id, override in sorted(r.active_rule_overrides.items()):
                parts: list[str] = []
                max_severity = override.get("max_severity")
                min_severity = override.get("min_severity")
                if max_severity is not None:
                    parts.append(f"max={max_severity}")
                if min_severity is not None:
                    parts.append(f"min={min_severity}")
                if parts:
                    override_parts.append(f"{rule_id} ({', '.join(parts)})")
            lines.append(f"  Overrides   {', '.join(override_parts)}")

        if r.rules_disabled:
            lines.append(f"  Rules off   {len(r.rules_disabled)} ({self._format_rule_list(r.rules_disabled)})")
        if r.disable_sources:
            lines.append(f"  Off source  {self._format_disable_sources(r.disable_sources)}")

        verdict = self._render_verdict()
        if verdict is not None:
            lines.append(f"  Verdict     {verdict}")

        lines.append(f"  Duration    {r.duration_seconds:.3f}s")
        if self._verbose:
            lines.append(f"  Cache       {r.cache_hits} hits / {r.cache_misses} misses")
        lines.append("")
        return "\n".join(lines)

    def _render_findings_table(self) -> str:
        risks = self._shown_findings
        if not risks:
            return ""

        table = Table(box=box.SQUARE, padding=(0, 1), expand=False)
        table.add_column("Skill", overflow="ellipsis")
        table.add_column("Rule", overflow="ellipsis")
        table.add_column("Score", justify="right", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Class", no_wrap=True, min_width=5, max_width=5)

        for finding in risks:
            score_cell: str | Text
            severity_cell: str | Text
            if self._color:
                score_cell = Text(str(finding.score), style=self._score_style_name(finding.score))
                severity_cell = Text(finding.severity, style=self._severity_style_name(finding.severity))
            else:
                score_cell = str(finding.score)
                severity_cell = finding.severity
            table.add_row(
                finding.skill,
                finding.rule_id,
                score_cell,
                severity_cell,
                _classification_short(finding.classification),
            )
        return f"  Findings\n{self._render_rich_table(table)}"

    def _render_grouped_table(self) -> str:
        """Render findings grouped by skill or rule with per-group aggregates."""
        findings = self._shown_findings
        if not findings:
            return ""

        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            key = finding.skill if self._group_by == "skill" else finding.rule_id
            groups.setdefault(key, []).append(finding)

        lines: list[str] = [f"  Findings (grouped by {self._group_by})", ""]

        for group_key in sorted(groups, key=lambda key: -max(f.score for f in groups[key])):
            group = groups[group_key]
            score = aggregate_overall_score(
                list(group),
                min_rule_score=self._result.aggregate_min_rule_score,
            )
            severity = aggregate_severity(
                score,
                high_min=self._result.high_severity_min,
                medium_min=self._result.medium_severity_min,
            )

            score_str = _color_score(score) if self._color else str(score)
            sev_str = _color_severity(severity) if self._color else severity
            lines.append(f"  [{group_key}]  score={score_str}  severity={sev_str}  findings={len(group)}")

            detail_key = "rule_id" if self._group_by == "skill" else "skill"
            detail_width = self._compute_grouped_detail_width(group, detail_key)
            for finding in sorted(group, key=lambda item: (-item.score, item.id)):
                detail = getattr(finding, detail_key)
                detail_text = self._truncate_cell(detail, detail_width)
                finding_score = self._format_score_cell(finding.score, 7)
                finding_sev = self._format_severity_cell(finding.severity)
                lines.append(f"    {detail_text:<{detail_width}}  {finding_score}  {finding_sev}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _truncate_cell(value: str, width: int) -> str:
        """Clamp cell text to column width with an ASCII ellipsis."""
        if width <= 0:
            return ""
        if len(value) <= width:
            return value
        if width <= 3:
            return value[:width]
        return f"{value[: width - 3]}..."

    def _format_score_cell(self, score: int, width: int) -> str:
        """Format score with right-padding before optional colorization."""
        text = self._truncate_cell(str(score), width).rjust(width)
        if not self._color:
            return text
        return _colorize(text, _score_color(score))

    @staticmethod
    def _score_style_name(score: int) -> str:
        if score >= 70:
            return "bold red"
        if score >= 40:
            return "bold yellow"
        return "bold green"

    def _format_severity_cell(self, severity: Severity, width: int | None = None) -> str:
        """Format severity with left-padding before optional colorization."""
        raw_text = severity if width is None else self._truncate_cell(severity, width).ljust(width)
        if not self._color:
            return raw_text
        color = SEVERITY_COLORS.get(severity, "")
        return _colorize(raw_text, color) if color else raw_text

    @staticmethod
    def _severity_style_name(severity: Severity) -> str:
        if severity == "high":
            return "bold red"
        if severity == "medium":
            return "bold yellow"
        return "bold green"

    def _render_rich_table(self, table: Table) -> str:
        """Render a rich table to text, preserving optional ANSI styles."""
        terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns
        console = Console(
            record=False,
            width=max(60, terminal_width - 2),
            force_terminal=self._color,
            no_color=not self._color,
            color_system="standard" if self._color else None,
            highlight=False,
        )
        with console.capture() as capture:
            console.print(table)
        rendered = capture.get().rstrip("\n")
        return self._indent_block(rendered, prefix="  ")

    @staticmethod
    def _indent_block(text: str, prefix: str = "  ") -> str:
        return "\n".join(f"{prefix}{line}" for line in text.splitlines())

    def _compute_grouped_detail_width(self, group: list[Finding], detail_key: str) -> int:
        """Compute grouped detail column width with terminal-aware cap."""
        min_width = 16
        max_width = 48
        preferred = max(
            min_width,
            *(len(getattr(finding, detail_key)) for finding in group),
        )
        detail_width = min(preferred, max_width)
        terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns
        # Leaves room for score/severity plus separators.
        max_for_detail = max(min_width, terminal_width - 24)
        return min(detail_width, max_for_detail)

    def _format_severity_breakdown(self, counts: dict[Severity, int]) -> str:
        """Render ``high/medium/low`` finding counts in fixed order."""
        parts: list[str] = []
        for severity in ("high", "medium", "low"):
            count = counts.get(severity, 0)
            label = _color_severity(severity) if self._color else severity
            parts.append(f"{count} {label}")
        return " · ".join(parts)

    def _format_filtered_summary(self, total_findings: int, shown_findings: int) -> str:
        """Render deterministic filtered-count details for header output."""
        filtered_count = max(0, total_findings - shown_findings)
        reason_counts = count_filtered_reasons(self._result.findings, self._filters)
        parts: list[str] = []
        if reason_counts["below_min_severity"] > 0 and self._filters.min_severity is not None:
            parts.append(f"{reason_counts['below_min_severity']} below {self._filters.min_severity}")
        if reason_counts["informational"] > 0:
            parts.append(f"{reason_counts['informational']} informational")
        if not parts:
            parts.append(str(filtered_count))
        return f"{' + '.join(parts)} filtered"

    @staticmethod
    def _format_top_rules(counts: dict[str, int], limit: int = 5) -> str:
        """Render top-N rules sorted by descending count, then rule id."""
        if not counts:
            return "none"
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        head = ranked[:limit]
        parts = [f"{rule_id} {count}" for rule_id, count in head]
        remaining = len(ranked) - len(head)
        if remaining > 0:
            parts.append(f"(+{remaining} more)")
        return " · ".join(parts)

    @staticmethod
    def _format_rule_list(rule_ids: tuple[str, ...], limit: int = 6) -> str:
        """Render a compact, deterministic preview of rule ids."""
        if len(rule_ids) <= limit:
            return ", ".join(rule_ids)
        shown = ", ".join(rule_ids[:limit])
        return f"{shown}, +{len(rule_ids) - limit} more"

    @staticmethod
    def _format_disable_sources(disable_sources: dict[str, RuleDisableSource]) -> str:
        """Render disable source counts in fixed source order."""
        counts = Counter(disable_sources.values())
        ordered_sources: tuple[RuleDisableSource, ...] = (
            "config",
            "cli-disable",
            "cli-only",
        )
        parts: list[str] = []
        for source in ordered_sources:
            count = counts.get(source, 0)
            if count > 0:
                parts.append(f"{source} {count}")
        return " · ".join(parts) if parts else "none"

    def _render_verdict(self) -> str | None:
        """Render CI threshold verdict when fail flags are configured."""
        if self._fail_on is None and self._fail_on_score is None:
            return None

        clauses: list[str] = []
        if self._fail_on is not None:
            threshold = SEVERITY_RANK[self._fail_on]
            matched = [
                finding for finding in self._result.findings if SEVERITY_RANK.get(finding.severity, 0) >= threshold
            ]
            if matched:
                clauses.append(f"{len(matched)} finding(s) >= {self._fail_on}")
            else:
                clauses.append(f"no findings >= {self._fail_on}")

        if self._fail_on_score is not None:
            score = self._result.aggregate_score
            if score >= self._fail_on_score:
                clauses.append(f"aggregate score {score} >= {self._fail_on_score}")
            else:
                clauses.append(f"aggregate score {score} < {self._fail_on_score}")

        state = "FAIL" if self._exit_code == 1 else "PASS"
        return f"{state} ({'; '.join(clauses)})"
