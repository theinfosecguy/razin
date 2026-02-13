"""String normalization helpers for skill names and comparisons."""

from __future__ import annotations

from razin.constants.discovery import SKILL_NAME_FALLBACK
from razin.constants.naming import (
    COLLAPSE_DASH_PATTERN,
    NON_ALNUM_DASH_PATTERN,
    NON_OUTPUT_NAME_PATTERN,
)


def sanitize_output_name(raw_name: str) -> str:
    """Normalize names for stable output directory paths."""
    normalized = raw_name.strip().lower()
    normalized = NON_OUTPUT_NAME_PATTERN.sub("-", normalized)
    normalized = COLLAPSE_DASH_PATTERN.sub("-", normalized)
    normalized = normalized.strip("-._")
    return normalized or SKILL_NAME_FALLBACK


def normalize_similarity_name(name: str) -> str:
    """Normalize names for typosquat similarity comparisons."""
    normalized = name.strip().lower()
    normalized = NON_ALNUM_DASH_PATTERN.sub("-", normalized)
    normalized = COLLAPSE_DASH_PATTERN.sub("-", normalized)
    return normalized.strip("-")
