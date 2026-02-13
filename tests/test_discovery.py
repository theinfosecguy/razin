"""Tests for discovery and skill-name derivation rules."""

from pathlib import Path

import pytest

from raisin.parsers import parse_skill_markdown_file
from raisin.scanner.discovery import derive_skill_name, sanitize_skill_name


def test_frontmatter_name_takes_precedence(fixtures_root: Path) -> None:
    root = (fixtures_root / "repos" / "manifest_skill").resolve()
    skill_file = root / "skills" / "tool" / "SKILL.md"
    parsed = parse_skill_markdown_file(skill_file)
    declared_name = None
    if isinstance(parsed.frontmatter, dict):
        name_value = parsed.frontmatter.get("name")
        if isinstance(name_value, str) and name_value.strip():
            declared_name = name_value.strip()

    assert derive_skill_name(skill_file, root, declared_name=declared_name) == "manifest-priority-skill"


def test_skill_folder_used_when_manifest_missing(fixtures_root: Path) -> None:
    root = (fixtures_root / "repos" / "basic").resolve()
    skill_file = root / "nested" / "skillset" / "SKILL.md"

    assert derive_skill_name(skill_file, root) == "skillset"


def test_sanitizes_fallback_name() -> None:
    assert sanitize_skill_name(" @Org/My Skill ") == "org-my-skill"


@pytest.mark.parametrize(
    ("raw_name", "expected"),
    [
        ("", "unnamed-skill"),
        ("....", "unnamed-skill"),
        ("A/B/C", "a-b-c"),
    ],
)
def test_sanitize_skill_name_edge_cases(raw_name: str, expected: str) -> None:
    assert sanitize_skill_name(raw_name) == expected
