"""Rich stdout reporter for scan results."""

from __future__ import annotations

from razin.constants.branding import ASCII_LOGO_LINES, SCAN_SUMMARY_TITLE
from razin.constants.reporting import (
    ANSI_GREEN,
    ANSI_RED,
    ANSI_RESET,
    ANSI_YELLOW,
    SEVERITY_COLORS,
)
from razin.model import ScanResult
from razin.types import Severity


def _colorize(text: str, color: str) -> str:
    return f"{color}{text}{ANSI_RESET}"


def _color_severity(severity: Severity) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    return _colorize(severity, color) if color else severity


def _color_score(score: int) -> str:
    if score >= 70:
        return _colorize(str(score), ANSI_RED)
    if score >= 40:
        return _colorize(str(score), ANSI_YELLOW)
    return _colorize(str(score), ANSI_GREEN)


class StdoutReporter:
    """Formats scan results as rich, human-readable stdout output."""

    def __init__(
        self,
        result: ScanResult,
        *,
        color: bool = True,
        verbose: bool = False,
    ) -> None:
        self._result = result
        self._color = color
        self._verbose = verbose

    def render(self) -> str:
        """Render the full stdout report as a single string."""
        sections = [
            self._render_header(),
            self._render_findings_table(),
        ]
        return "\n".join(section for section in sections if section)

    def _render_header(self) -> str:
        r = self._result
        sep = "  " + "─" * 38

        score_str = str(r.aggregate_score)
        severity_value = r.aggregate_severity
        sev_str: str = severity_value
        if self._color:
            score_str = _color_score(r.aggregate_score)
            sev_str = _color_severity(severity_value)
        score_pad = len(score_str) - len(str(r.aggregate_score))
        sev_pad = len(sev_str) - len(severity_value)

        counts = r.counts_by_severity
        parts: list[str] = []
        for sev in ("high", "medium", "low"):
            count = counts.get(sev, 0)
            if count:
                label = _color_severity(sev) if self._color else sev
                pad = _ansi_pad(label, sev)
                parts.append(f"{count} {label}" + "" * pad)
        breakdown = " \u00b7 ".join(parts) if parts else "none"

        lines = [
            "",
            f"  {ASCII_LOGO_LINES[0]}",
            f"  {ASCII_LOGO_LINES[1]}",
            f"  {SCAN_SUMMARY_TITLE}",
            sep,
            "",
            f"  Risk Score  {score_str:>{14 + score_pad}}" f"              {sev_str}{' ' * sev_pad}",
            f"  Files       {r.scanned_files:>14}",
            f"  Findings    {r.total_findings:>14}   ({breakdown})",
            f"  Duration    {r.duration_seconds:>13.3f}s",
        ]
        if self._verbose:
            lines.append(f"  Cache       {r.cache_hits:>10} hits / {r.cache_misses} misses")
        lines.append("")
        return "\n".join(lines)

    def _render_findings_table(self) -> str:
        risks = self._result.findings
        if not risks:
            return ""

        # Column widths (content only)
        w_skill = 25
        w_rule = 20
        w_score = 7
        w_sev = 8

        def _hline(left: str, mid: str, right: str) -> str:
            return (
                f"  {left}{'─' * (w_skill + 2)}{mid}{'─' * (w_rule + 2)}"
                f"{mid}{'─' * (w_score + 2)}{mid}{'─' * (w_sev + 2)}{right}"
            )

        top_border = _hline("┌", "┬", "┐")
        hdr_sep = _hline("├", "┼", "┤")
        bot_border = _hline("└", "┴", "┘")

        hdr = f"  │ {'Skill':<{w_skill}} │ {'Rule':<{w_rule}}" f" │ {'Score':>{w_score}} │ {'Severity':<{w_sev}} │"

        lines = ["  Findings", top_border, hdr, hdr_sep]
        for finding in risks:
            score_str = _color_score(finding.score) if self._color else str(finding.score)
            sev_str = _color_severity(finding.severity) if self._color else finding.severity
            score_pad = len(score_str) - len(str(finding.score))
            sev_pad = len(sev_str) - len(finding.severity)
            row = (
                f"  │ {finding.skill:<{w_skill}} │ {finding.rule_id:<{w_rule}}"
                f" │ {score_str:>{w_score + score_pad}}"
                f" │ {sev_str:<{w_sev + sev_pad}} │"
            )
            lines.append(row)
        lines.append(bot_border)
        return "\n".join(lines)


def _ansi_pad(colored: str, plain: str) -> int:
    """Return the extra characters added by ANSI escapes."""
    return len(colored) - len(plain)
