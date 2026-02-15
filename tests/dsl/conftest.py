"""Shared fixtures and helpers for DSL test modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _skill_file(tmp_path: Path, content: str) -> Path:
    """Create a temporary SKILL.md with the given content."""
    f = tmp_path / "SKILL.md"
    f.write_text(content, encoding="utf-8")
    return f


def _minimal_rule(**overrides: Any) -> dict[str, Any]:
    """Return a minimal valid rule dict, merged with *overrides*."""
    base: dict[str, Any] = {
        "rule_id": "TEST_RULE",
        "version": 1,
        "metadata": {
            "title": "Test rule",
            "description": "Test description",
            "recommendation": "Fix it",
            "confidence": "medium",
        },
        "scoring": {"base_score": 50},
        "match": {
            "source": "fields",
            "strategy": "key_pattern_match",
            "keywords": ["test"],
        },
        "dedupe": True,
    }
    base.update(overrides)
    return base


def _write_rule_file(path: Path, **overrides: Any) -> Path:
    """Write a minimal rule YAML file to *path*."""
    payload = _minimal_rule(**overrides)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path
