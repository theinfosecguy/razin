"""Schema constants for DSL v1 rule files."""

from __future__ import annotations

VALID_STRATEGIES: frozenset[str] = frozenset(
    {
        "url_domain_filter",
        "ip_address_scan",
        "key_pattern_match",
        "field_pattern_match",
        "entropy_check",
        "hint_count",
        "keyword_in_text",
        "token_scan",
        "frontmatter_check",
        "typosquat_check",
        "bundled_scripts_check",
        "hidden_instruction_scan",
        "data_sensitivity_check",
    }
)

VALID_CONFIDENCES: frozenset[str] = frozenset({"low", "medium", "high"})

VALID_SOURCES: frozenset[str] = frozenset({"fields", "keys", "raw_text", "frontmatter", "file_system"})

REQUIRED_TOP_KEYS: frozenset[str] = frozenset({"rule_id", "version", "metadata", "scoring", "match"})
ALLOWED_TOP_KEYS: frozenset[str] = REQUIRED_TOP_KEYS | {
    "dedupe",
    "profiles",
    "public_rule_id",
}

REQUIRED_METADATA_KEYS: frozenset[str] = frozenset({"title", "recommendation", "confidence"})
ALLOWED_METADATA_KEYS: frozenset[str] = REQUIRED_METADATA_KEYS | {
    "description",
    "description_template",
}

VALID_PROFILE_NAMES: frozenset[str] = frozenset({"strict", "balanced", "audit"})
ALLOWED_PROFILE_KEYS: frozenset[str] = frozenset({"score_override"})
