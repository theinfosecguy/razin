"""Tests for SKILL.md parsing and evidence extraction."""

from pathlib import Path

import pytest

from razin.exceptions import SkillParseError
from razin.parsers import parse_skill_markdown_file


def test_parse_skill_extracts_fields_with_lines(basic_repo_root: Path) -> None:
    fixture_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(fixture_file)

    values = {field.value for field in parsed.fields}
    assert "name: opena1-helper" not in values  # frontmatter excluded from body fields
    assert "token: ${API_TOKEN}" in values

    token_field = next(field for field in parsed.fields if "token: ${API_TOKEN}" in field.value)
    assert token_field.line == 11
    assert "token:" in token_field.snippet


def test_parse_skill_frontmatter_requires_mcp(basic_repo_root: Path) -> None:
    fixture_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(fixture_file)

    assert isinstance(parsed.frontmatter, dict)
    requires = parsed.frontmatter.get("requires")
    assert isinstance(requires, dict)
    assert requires.get("mcp")


def test_parse_skill_raises_for_invalid_frontmatter(tmp_path: Path) -> None:
    invalid_md = tmp_path / "SKILL.md"
    invalid_md.write_text("""---\nname: [broken\n---\n# Broken\n""", encoding="utf-8")

    with pytest.raises(SkillParseError):
        parse_skill_markdown_file(invalid_md)


def test_parse_skill_raises_for_unterminated_frontmatter(tmp_path: Path) -> None:
    invalid_md = tmp_path / "SKILL.md"
    invalid_md.write_text("""---\nname: missing-end\n# Broken\n""", encoding="utf-8")

    with pytest.raises(SkillParseError):
        parse_skill_markdown_file(invalid_md)


def test_parse_skill_allows_empty_frontmatter(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("""---\n---\n# Title\n""", encoding="utf-8")

    parsed = parse_skill_markdown_file(skill_md)

    assert parsed.frontmatter is None
    assert parsed.body == "# Title"


def test_parse_skill_frontmatter_excluded_fields_start_after_frontmatter(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "\n".join(
            [
                "---",
                "name: sample",
                "requires:",
                "  mcp:",
                "    - rube",
                "---",
                "# Body",
                "token: ${API_TOKEN}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    parsed = parse_skill_markdown_file(skill_md)

    assert parsed.fields[0].value == "# Body"
    assert parsed.fields[0].line == 7
    assert all(not field.value.startswith("name:") for field in parsed.fields)


def test_parse_skill_without_frontmatter_starts_fields_at_line_one(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("# Body\ntoken: ${API_TOKEN}\n", encoding="utf-8")

    parsed = parse_skill_markdown_file(skill_md)

    assert parsed.fields[0].line == 1
    assert parsed.fields[1].line == 2


def test_parse_skill_marks_fenced_code_block_lines(tmp_path: Path) -> None:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "\n".join(
            [
                "---",
                "name: sample",
                "---",
                "~~~yaml",
                "apiKey: your-api-key",
                "~~~",
                "apiKey: sk-live-abc123",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    parsed = parse_skill_markdown_file(skill_md)

    placeholder = next(field for field in parsed.fields if field.value == "apiKey: your-api-key")
    real_value = next(field for field in parsed.fields if field.value == "apiKey: sk-live-abc123")

    assert placeholder.in_code_block is True
    assert real_value.in_code_block is False
