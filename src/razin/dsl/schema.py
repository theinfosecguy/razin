"""Strict schema validation for DSL v1 rule files.

Validates parsed YAML dicts at load time. Raises DslSchemaError on any
violation — fail-fast, no skip-and-continue.
"""

from __future__ import annotations

from typing import Any

from razin.constants.dsl_schema import (
    ALLOWED_METADATA_KEYS,
    ALLOWED_PROFILE_KEYS,
    ALLOWED_TOP_KEYS,
    REQUIRED_METADATA_KEYS,
    REQUIRED_TOP_KEYS,
    VALID_CLASSIFICATIONS,
    VALID_CONFIDENCES,
    VALID_PROFILE_NAMES,
    VALID_SOURCES,
    VALID_STRATEGIES,
)
from razin.exceptions.dsl import DslSchemaError


def validate_rule(data: dict[str, Any], source_path: str) -> None:
    """Validate a YAML rule dict. Raises DslSchemaError on any violation."""
    if not isinstance(data, dict):
        raise DslSchemaError(f"{source_path}: rule must be a mapping, got {type(data).__name__}")

    unknown_top = set(data.keys()) - ALLOWED_TOP_KEYS
    if unknown_top:
        raise DslSchemaError(f"{source_path}: unknown top-level keys: {sorted(unknown_top)}")

    for key in REQUIRED_TOP_KEYS:
        if key not in data:
            raise DslSchemaError(f"{source_path}: missing required key '{key}'")

    _validate_rule_id(data["rule_id"], source_path)
    if "public_rule_id" in data:
        _validate_rule_id(data["public_rule_id"], source_path)
    _validate_version(data["version"], source_path)
    _validate_metadata(data["metadata"], source_path)
    _validate_scoring(data["scoring"], source_path)
    _validate_match(data["match"], source_path)

    if "dedupe" in data and not isinstance(data["dedupe"], bool):
        raise DslSchemaError(f"{source_path}: 'dedupe' must be a boolean")

    if "profiles" in data:
        _validate_profiles(data["profiles"], source_path)


def _validate_rule_id(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DslSchemaError(f"{path}: 'rule_id' must be a non-empty string")


def _validate_version(value: Any, path: str) -> None:
    if not isinstance(value, int) or value != 1:
        raise DslSchemaError(f"{path}: 'version' must be 1 (DSL v1), got {value!r}")


def _validate_metadata(metadata: Any, path: str) -> None:
    if not isinstance(metadata, dict):
        raise DslSchemaError(f"{path}: 'metadata' must be a mapping")

    unknown = set(metadata.keys()) - ALLOWED_METADATA_KEYS
    if unknown:
        raise DslSchemaError(f"{path}: unknown metadata keys: {sorted(unknown)}")

    for key in REQUIRED_METADATA_KEYS:
        if key not in metadata:
            raise DslSchemaError(f"{path}: metadata missing required key '{key}'")

    if metadata["confidence"] not in VALID_CONFIDENCES:
        raise DslSchemaError(
            f"{path}: confidence must be one of {sorted(VALID_CONFIDENCES)}, got {metadata['confidence']!r}"
        )

    if "classification" in metadata and metadata["classification"] not in VALID_CLASSIFICATIONS:
        raise DslSchemaError(
            f"{path}: classification must be one of {sorted(VALID_CLASSIFICATIONS)}, "
            f"got {metadata['classification']!r}"
        )

    if "description" not in metadata and "description_template" not in metadata:
        raise DslSchemaError(f"{path}: metadata must have 'description' or 'description_template'")


def _validate_scoring(scoring: Any, path: str) -> None:
    if not isinstance(scoring, dict):
        raise DslSchemaError(f"{path}: 'scoring' must be a mapping")
    if "base_score" not in scoring:
        raise DslSchemaError(f"{path}: scoring missing 'base_score'")
    base_score = scoring["base_score"]
    if not isinstance(base_score, int) or not (0 <= base_score <= 100):
        raise DslSchemaError(f"{path}: scoring.base_score must be int 0-100, got {base_score!r}")


def _validate_match(match: Any, path: str) -> None:
    if not isinstance(match, dict):
        raise DslSchemaError(f"{path}: 'match' must be a mapping")
    if "source" not in match:
        raise DslSchemaError(f"{path}: match missing 'source'")
    if match["source"] not in VALID_SOURCES:
        raise DslSchemaError(f"{path}: match.source must be one of {sorted(VALID_SOURCES)}, got {match['source']!r}")
    if "strategy" not in match:
        raise DslSchemaError(f"{path}: match missing 'strategy'")
    if match["strategy"] not in VALID_STRATEGIES:
        raise DslSchemaError(
            f"{path}: match.strategy must be one of {sorted(VALID_STRATEGIES)}, got {match['strategy']!r}"
        )


def _validate_profiles(profiles: Any, path: str) -> None:
    """Validate the optional profiles overlay section."""
    if not isinstance(profiles, dict):
        raise DslSchemaError(f"{path}: 'profiles' must be a mapping")

    for profile_name, overrides in profiles.items():
        if profile_name not in VALID_PROFILE_NAMES:
            raise DslSchemaError(
                f"{path}: unknown profile '{profile_name}', must be one of {sorted(VALID_PROFILE_NAMES)}"
            )
        if not isinstance(overrides, dict):
            raise DslSchemaError(f"{path}: profiles.{profile_name} must be a mapping")

        unknown = set(overrides.keys()) - ALLOWED_PROFILE_KEYS
        if unknown:
            raise DslSchemaError(f"{path}: unknown keys in profiles.{profile_name}: {sorted(unknown)}")

        if "score_override" in overrides:
            score = overrides["score_override"]
            if not isinstance(score, int) or not (0 <= score <= 100):
                raise DslSchemaError(f"{path}: profiles.{profile_name}.score_override must be int 0-100, got {score!r}")
