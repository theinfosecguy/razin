"""Configuration defaults and filenames."""

from __future__ import annotations

from razin.constants.docs import DEFAULT_TOOL_PREFIXES

CONFIG_FILENAME: str = "razin.yaml"
DEFAULT_MAX_FILE_MB: int = 2

RULE_OVERRIDE_ALLOWED_KEYS: frozenset[str] = frozenset({"max_severity", "min_severity"})
RULE_OVERRIDE_ALLOWED_SEVERITIES: frozenset[str] = frozenset({"high", "medium", "low"})

DEFAULT_SKILL_GLOBS: tuple[str, ...] = ("**/SKILL.md",)

DEFAULT_DETECTORS: tuple[str, ...] = (
    "NET_RAW_IP",
    "NET_UNKNOWN_DOMAIN",
    "NET_DOC_DOMAIN",
    "SECRET_REF",
    "EXEC_FIELDS",
    "OPAQUE_BLOB",
    "TYPOSQUAT",
    "BUNDLED_SCRIPTS",
    "MCP_REQUIRED",
    "MCP_ENDPOINT",
    "MCP_DENYLIST",
    "TOOL_INVOCATION",
    "DYNAMIC_SCHEMA",
    "AUTH_CONNECTION",
    "PROMPT_INJECTION",
    "HIDDEN_INSTRUCTION",
    "DATA_SENSITIVITY",
)

DEFAULT_TOOL_PREFIXES_CONFIG: tuple[str, ...] = DEFAULT_TOOL_PREFIXES
