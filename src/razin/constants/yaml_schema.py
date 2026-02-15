"""Schema constants for legacy YAML-defined detector rules."""

from __future__ import annotations

VALID_STRATEGIES: frozenset[str] = frozenset(
    {
        "url_domain_filter",
        "hint_count",
        "entropy_check",
    }
)

VALID_CONFIDENCES: frozenset[str] = frozenset({"low", "medium", "high"})

VALID_SOURCES: frozenset[str] = frozenset({"fields", "raw_text"})

REQUIRED_TOP_KEYS: frozenset[str] = frozenset(
    {
        "rule_id",
        "version",
        "metadata",
        "scoring",
        "match",
    }
)

REQUIRED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "title",
        "recommendation",
        "confidence",
    }
)

ALLOWED_TOP_KEYS: frozenset[str] = REQUIRED_TOP_KEYS | {"dedupe"}
