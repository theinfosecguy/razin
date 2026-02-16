"""Constants for report file names, atomic writing, and stdout formatting."""

from __future__ import annotations

FINDINGS_FILENAME: str = "findings.json"
SUMMARY_FILENAME: str = "summary.json"
CSV_FINDINGS_FILENAME: str = "findings.csv"
SARIF_FINDINGS_FILENAME: str = "findings.sarif"
REPORT_TEMP_PREFIX: str = ".tmp-"
REPORT_TEMP_SUFFIX: str = ".json"

SCHEMA_VERSION: str = "1.0.0"

VALID_OUTPUT_FORMATS: frozenset[str] = frozenset({"json", "csv", "sarif"})
DEFAULT_OUTPUT_FORMAT: str = "json"

CSV_COLUMNS: tuple[str, ...] = (
    "id",
    "skill",
    "rule_id",
    "severity",
    "score",
    "confidence",
    "path",
    "line",
    "title",
    "description",
    "recommendation",
)

SARIF_VERSION: str = "2.1.0"
SARIF_SCHEMA_URI: str = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
SARIF_TOOL_NAME: str = "RAZIN"

SARIF_SEVERITY_MAP: dict[str, str] = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# ANSI escape codes for terminal colouring.
ANSI_RESET: str = "\033[0m"
ANSI_BOLD: str = "\033[1m"
ANSI_RED: str = "\033[31;1m"
ANSI_YELLOW: str = "\033[33;1m"
ANSI_GREEN: str = "\033[32;1m"
ANSI_DIM: str = "\033[2m"

SEVERITY_COLORS: dict[str, str] = {
    "high": ANSI_RED,
    "medium": ANSI_YELLOW,
    "low": ANSI_GREEN,
}
