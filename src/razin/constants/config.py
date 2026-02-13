"""Configuration defaults and filenames."""

from __future__ import annotations

from razin.constants.docs import DEFAULT_TOOL_PREFIXES

CONFIG_FILENAME: str = "razin.yaml"
DEFAULT_MAX_FILE_MB: int = 2

DEFAULT_SKILL_GLOBS: tuple[str, ...] = ("**/SKILL.md",)

DEFAULT_DETECTORS: tuple[str, ...] = (
    "NET_RAW_IP",
    "NET_UNKNOWN_DOMAIN",
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
    "EXTERNAL_URLS",
)

DEFAULT_TOOL_PREFIXES_CONFIG: tuple[str, ...] = DEFAULT_TOOL_PREFIXES
