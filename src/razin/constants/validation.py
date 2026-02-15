"""Stable validation error codes and allowed-key sets for config and DSL rule validation."""

from __future__ import annotations

CFG001: str = "CFG001"  # config file not found (explicit --config)
CFG002: str = "CFG002"  # invalid YAML parse
CFG003: str = "CFG003"  # top-level value is not a mapping
CFG004: str = "CFG004"  # unknown top-level key
CFG005: str = "CFG005"  # invalid value type
CFG006: str = "CFG006"  # invalid enum value
CFG007: str = "CFG007"  # value out of range
CFG008: str = "CFG008"  # contradictory detector config
CFG009: str = "CFG009"  # invalid nested mapping
CFG010: str = "CFG010"  # root directory not found

RULE001: str = "RULE001"  # rule file not found / unreadable
RULE002: str = "RULE002"  # invalid file extension
RULE003: str = "RULE003"  # invalid YAML parse
RULE004: str = "RULE004"  # top-level value is not a mapping
RULE005: str = "RULE005"  # unknown top-level key
RULE006: str = "RULE006"  # missing required field
RULE007: str = "RULE007"  # invalid value / enum
RULE008: str = "RULE008"  # duplicate rule_id
RULE009: str = "RULE009"  # source conflict (--rules-dir + --rule-file)

ALL_CFG_CODES: tuple[str, ...] = (
    CFG001,
    CFG002,
    CFG003,
    CFG004,
    CFG005,
    CFG006,
    CFG007,
    CFG008,
    CFG009,
    CFG010,
)

ALL_RULE_CODES: tuple[str, ...] = (
    RULE001,
    RULE002,
    RULE003,
    RULE004,
    RULE005,
    RULE006,
    RULE007,
    RULE008,
    RULE009,
)

ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "profile",
        "allowlist_domains",
        "ignore_default_allowlist",
        "strict_subdomains",
        "denylist_domains",
        "mcp_allowlist_domains",
        "mcp_denylist_domains",
        "tool_prefixes",
        "detectors",
        "typosquat",
        "tool_tier_keywords",
        "skill_globs",
        "max_file_mb",
    }
)

ALLOWED_DETECTOR_KEYS: frozenset[str] = frozenset({"enabled", "disabled"})
ALLOWED_TYPOSQUAT_KEYS: frozenset[str] = frozenset({"baseline"})
ALLOWED_TOOL_TIER_KEYS: frozenset[str] = frozenset({"destructive", "write"})

LIST_OF_STRINGS_KEYS: tuple[str, ...] = (
    "allowlist_domains",
    "denylist_domains",
    "mcp_allowlist_domains",
    "mcp_denylist_domains",
    "tool_prefixes",
    "skill_globs",
)
