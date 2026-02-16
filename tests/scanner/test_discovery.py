"""Tests for discovery, skill-name derivation, and name collection."""

import os
from pathlib import Path

import pytest

from razin.parsers import parse_skill_markdown_file
from razin.scanner.discovery import (
    collect_all_skill_names,
    derive_skill_name,
    discover_skill_files,
    sanitize_skill_name,
)


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


def _write_skill(folder: Path, frontmatter: str = "", body: str = "# Skill\nA skill.\n") -> Path:
    """Create a SKILL.md file inside *folder* with optional frontmatter."""
    folder.mkdir(parents=True, exist_ok=True)
    content = f"---\n{frontmatter}---\n{body}" if frontmatter else body
    path = folder / "SKILL.md"
    path.write_text(content, encoding="utf-8")
    return path


def test_collect_names_from_frontmatter(tmp_path: Path) -> None:
    """Skills with declared names in frontmatter are included in the baseline."""
    _write_skill(tmp_path / "alpha", frontmatter="name: Alpha Skill\n")
    _write_skill(tmp_path / "beta", frontmatter="name: Beta Tool\n")
    files = sorted(tmp_path.rglob("SKILL.md"))

    names = collect_all_skill_names(files, tmp_path)

    assert "alpha-skill" in names
    assert "beta-tool" in names


def test_collect_names_folder_fallback(tmp_path: Path) -> None:
    """Skills without frontmatter use folder name as the collected name."""
    _write_skill(tmp_path / "my-cool-skill")
    files = sorted(tmp_path.rglob("SKILL.md"))

    names = collect_all_skill_names(files, tmp_path)

    assert "my-cool-skill" in names


def test_collect_names_deduplicates(tmp_path: Path) -> None:
    """Two skills producing the same normalized name appear only once."""
    _write_skill(tmp_path / "slack-automation", frontmatter="name: slack-automation\n")
    _write_skill(tmp_path / "Slack_Automation", frontmatter="name: Slack_Automation\n")
    files = sorted(tmp_path.rglob("SKILL.md"))

    names = collect_all_skill_names(files, tmp_path)

    assert names.count("slack-automation") == 1


def test_collect_names_handles_malformed_yaml(tmp_path: Path) -> None:
    """Broken YAML frontmatter falls back to folder name without crashing."""
    folder = tmp_path / "bad-yaml"
    folder.mkdir()
    (folder / "SKILL.md").write_text("---\n: invalid: yaml: [[\n---\n# Body\n", encoding="utf-8")
    files = [folder / "SKILL.md"]

    names = collect_all_skill_names(files, tmp_path)

    assert "bad-yaml" in names


def test_collect_names_handles_binary_file(tmp_path: Path) -> None:
    """Binary SKILL.md is excluded from baseline without crashing."""
    folder = tmp_path / "binary-skill"
    folder.mkdir()
    (folder / "SKILL.md").write_bytes(b"\x00\x01\x02\xff\xfe\xfd")
    files = [folder / "SKILL.md"]

    names = collect_all_skill_names(files, tmp_path)

    assert "binary-skill" not in names


def test_collect_names_empty_list(tmp_path: Path) -> None:
    """Empty file list returns empty tuple."""
    assert collect_all_skill_names([], tmp_path) == ()


def test_collect_names_single_file(tmp_path: Path) -> None:
    """Single file returns tuple with one name."""
    _write_skill(tmp_path / "solo-skill", frontmatter="name: solo-skill\n")
    files = sorted(tmp_path.rglob("SKILL.md"))

    names = collect_all_skill_names(files, tmp_path)

    assert len(names) == 1
    assert "solo-skill" in names


def test_collect_names_includes_both_folder_and_frontmatter(tmp_path: Path) -> None:
    """When folder and frontmatter names differ, both are included."""
    _write_skill(tmp_path / "slack-automation", frontmatter="name: SlackBot\n")
    files = sorted(tmp_path.rglob("SKILL.md"))

    names = collect_all_skill_names(files, tmp_path)

    assert "slackbot" in names
    assert "slack-automation" in names


def test_collect_names_bom_prefixed_frontmatter(tmp_path: Path) -> None:
    """BOM-prefixed SKILL.md files have their frontmatter name extracted correctly."""
    folder = tmp_path / "bom-skill"
    folder.mkdir()
    content = "\ufeff---\nname: BomBot\n---\n# Skill\nA skill.\n"
    (folder / "SKILL.md").write_text(content, encoding="utf-8")
    files = [folder / "SKILL.md"]

    names = collect_all_skill_names(files, tmp_path)

    assert "bombot" in names


def test_collect_names_alt_delimiter_frontmatter(tmp_path: Path) -> None:
    """Frontmatter closed with ``...`` delimiter has its name extracted correctly."""
    folder = tmp_path / "alt-delim"
    folder.mkdir()
    content = "---\nname: AltBot\n...\n# Skill\nA skill.\n"
    (folder / "SKILL.md").write_text(content, encoding="utf-8")
    files = [folder / "SKILL.md"]

    names = collect_all_skill_names(files, tmp_path)

    assert "altbot" in names


def test_discover_symlink_outside_root(tmp_path: Path) -> None:
    """Symlinked SKILL.md resolving outside root does not crash discovery."""
    external = tmp_path / "external"
    external.mkdir()
    real_skill = external / "SKILL.md"
    real_skill.write_text("---\nname: external\n---\n# External\n", encoding="utf-8")

    root = tmp_path / "workspace"
    skill_dir = root / "linked-skill"
    skill_dir.mkdir(parents=True)
    link_path = skill_dir / "SKILL.md"
    os.symlink(real_skill, link_path)

    files = discover_skill_files(root, ("**/SKILL.md",), max_file_mb=10)

    assert len(files) == 1


def test_discover_symlink_inside_root(tmp_path: Path) -> None:
    """Symlinked SKILL.md resolving inside root works normally."""
    root = tmp_path / "workspace"
    real_dir = root / "real-skill"
    real_dir.mkdir(parents=True)
    (real_dir / "SKILL.md").write_text("---\nname: real\n---\n# Real\n", encoding="utf-8")

    link_dir = root / "link-skill"
    link_dir.mkdir(parents=True)
    os.symlink(real_dir / "SKILL.md", link_dir / "SKILL.md")

    files = discover_skill_files(root, ("**/SKILL.md",), max_file_mb=10)

    assert len(files) >= 1


def test_discover_symlink_deterministic_order(tmp_path: Path) -> None:
    """Discovery with mixed real and symlinked files produces deterministic order."""
    external = tmp_path / "external"
    external.mkdir()
    (external / "SKILL.md").write_text("---\nname: ext\n---\n# Ext\n", encoding="utf-8")

    root = tmp_path / "workspace"
    _write_skill(root / "alpha-skill", frontmatter="name: alpha\n")
    link_dir = root / "beta-linked"
    link_dir.mkdir(parents=True)
    os.symlink(external / "SKILL.md", link_dir / "SKILL.md")

    first = discover_skill_files(root, ("**/SKILL.md",), max_file_mb=10)
    second = discover_skill_files(root, ("**/SKILL.md",), max_file_mb=10)

    assert first == second


def test_collect_names_binary_excluded_from_baseline(tmp_path: Path) -> None:
    """Binary file does not contribute to typosquat baseline, preventing ghost matches."""
    binary_dir = tmp_path / "slack-automation"
    binary_dir.mkdir()
    (binary_dir / "SKILL.md").write_bytes(b"\x89PNG\r\n\x1a\n\x00\xb0\xff\xfe")
    _write_skill(tmp_path / "gmail-tool", frontmatter="name: gmail-tool\n")
    files = sorted(tmp_path.rglob("SKILL.md"))

    names = collect_all_skill_names(files, tmp_path)

    assert "slack-automation" not in names
    assert "gmail-tool" in names
