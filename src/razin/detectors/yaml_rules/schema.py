"""Schema validation for YAML-defined detector rules.

Validates YAML rule definitions against the expected structure at load time.
Raises ConfigError on any schema violation (fail-fast).
"""

from __future__ import annotations

from typing import Any

from razin.exceptions import ConfigError

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


def validate_yaml_rule(data: dict[str, Any], source_path: str) -> None:
    """Validate a parsed YAML rule dictionary.

    Raises ConfigError with a descriptive message on any violation.
    """
    if not isinstance(data, dict):
        raise ConfigError(f"YAML rule at {source_path} must be a mapping, got {type(data).__name__}")

    unknown_top = set(data.keys()) - ALLOWED_TOP_KEYS
    if unknown_top:
        raise ConfigError(f"YAML rule at {source_path} has unknown keys: {sorted(unknown_top)}")

    for key in REQUIRED_TOP_KEYS:
        if key not in data:
            raise ConfigError(f"YAML rule at {source_path} missing required key '{key}'")

    _validate_rule_id(data["rule_id"], source_path)
    _validate_version(data["version"], source_path)
    _validate_metadata(data["metadata"], source_path)
    _validate_scoring(data["scoring"], source_path)
    _validate_match(data["match"], source_path)

    if "dedupe" in data and not isinstance(data["dedupe"], bool):
        raise ConfigError(f"YAML rule at {source_path}: 'dedupe' must be a boolean")


def _validate_rule_id(value: Any, source_path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"YAML rule at {source_path}: 'rule_id' must be a non-empty string")


def _validate_version(value: Any, source_path: str) -> None:
    if not isinstance(value, int) or value < 1:
        raise ConfigError(f"YAML rule at {source_path}: 'version' must be a positive integer")


def _validate_metadata(metadata: Any, source_path: str) -> None:
    if not isinstance(metadata, dict):
        raise ConfigError(f"YAML rule at {source_path}: 'metadata' must be a mapping")

    for key in REQUIRED_METADATA_KEYS:
        if key not in metadata:
            raise ConfigError(f"YAML rule at {source_path}: metadata missing required key '{key}'")

    confidence = metadata["confidence"]
    if confidence not in VALID_CONFIDENCES:
        raise ConfigError(
            f"YAML rule at {source_path}: metadata.confidence must be one of "
            f"{sorted(VALID_CONFIDENCES)}, got {confidence!r}"
        )

    if "description" not in metadata and "description_template" not in metadata:
        raise ConfigError(f"YAML rule at {source_path}: metadata must have 'description' or 'description_template'")


def _validate_scoring(scoring: Any, source_path: str) -> None:
    if not isinstance(scoring, dict):
        raise ConfigError(f"YAML rule at {source_path}: 'scoring' must be a mapping")
    if "base_score" not in scoring:
        raise ConfigError(f"YAML rule at {source_path}: scoring missing 'base_score'")
    base_score = scoring["base_score"]
    if not isinstance(base_score, int) or not (0 <= base_score <= 100):
        raise ConfigError(f"YAML rule at {source_path}: scoring.base_score must be int 0-100")


def _validate_match(match: Any, source_path: str) -> None:
    if not isinstance(match, dict):
        raise ConfigError(f"YAML rule at {source_path}: 'match' must be a mapping")
    if "source" not in match:
        raise ConfigError(f"YAML rule at {source_path}: match missing 'source'")
    if match["source"] not in VALID_SOURCES:
        raise ConfigError(
            f"YAML rule at {source_path}: match.source must be one of "
            f"{sorted(VALID_SOURCES)}, got {match['source']!r}"
        )
    if "strategy" not in match:
        raise ConfigError(f"YAML rule at {source_path}: match missing 'strategy'")
    if match["strategy"] not in VALID_STRATEGIES:
        raise ConfigError(
            f"YAML rule at {source_path}: match.strategy must be one of "
            f"{sorted(VALID_STRATEGIES)}, got {match['strategy']!r}"
        )

    strategy = match["strategy"]
    if strategy == "hint_count":
        _validate_hint_count_match(match, source_path)
    elif strategy == "entropy_check":
        _validate_entropy_check_match(match, source_path)
    elif strategy == "url_domain_filter":
        _validate_url_domain_filter_match(match, source_path)


def _validate_hint_count_match(match: dict[str, Any], source_path: str) -> None:
    for key in ("strong_hints", "min_hint_count"):
        if key not in match:
            raise ConfigError(f"YAML rule at {source_path}: hint_count strategy requires '{key}'")
    if not isinstance(match["strong_hints"], list):
        raise ConfigError(f"YAML rule at {source_path}: strong_hints must be a list")
    if not isinstance(match["min_hint_count"], int) or match["min_hint_count"] < 1:
        raise ConfigError(f"YAML rule at {source_path}: min_hint_count must be a positive integer")


def _validate_entropy_check_match(match: dict[str, Any], source_path: str) -> None:
    for key in ("min_length", "min_entropy"):
        if key not in match:
            raise ConfigError(f"YAML rule at {source_path}: entropy_check strategy requires '{key}'")
    if not isinstance(match["min_length"], int) or match["min_length"] < 1:
        raise ConfigError(f"YAML rule at {source_path}: min_length must be a positive integer")
    if not isinstance(match["min_entropy"], (int, float)):
        raise ConfigError(f"YAML rule at {source_path}: min_entropy must be a number")


def _validate_url_domain_filter_match(match: dict[str, Any], source_path: str) -> None:
    for key in ("url_filter", "domain_check"):
        if key not in match:
            raise ConfigError(f"YAML rule at {source_path}: url_domain_filter strategy requires '{key}'")
    if not isinstance(match["url_filter"], str):
        raise ConfigError(f"YAML rule at {source_path}: url_filter must be a string")
    if not isinstance(match["domain_check"], str):
        raise ConfigError(f"YAML rule at {source_path}: domain_check must be a string")
