"""Parser for SKILL.md files with YAML frontmatter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from razin.constants.parsing import (
    FENCED_CODE_BLOCK_PATTERN,
    FRONTMATTER_ALT_DELIMITER,
    FRONTMATTER_DELIMITER,
    KEY_LINE_EXCLUDE,
    KEY_LINE_PATTERN,
    SNIPPET_MAX_LENGTH,
)
from razin.exceptions import SkillParseError
from razin.model import DocumentField, DocumentKey, ParsedSkillDocument


def parse_skill_markdown_file(path: Path) -> ParsedSkillDocument:
    """Parse a SKILL.md file and extract frontmatter plus line metadata."""
    raw_text = path.read_text(encoding="utf-8")
    normalized = raw_text.lstrip("\ufeff")
    lines = normalized.splitlines()

    frontmatter: dict[str, Any] | None = None
    body_lines = lines

    if lines and lines[0].strip() == FRONTMATTER_DELIMITER:
        frontmatter_end = _find_frontmatter_end(lines)
        if frontmatter_end is None:
            raise SkillParseError(f"Unterminated frontmatter block in {path}")

        frontmatter_text = "\n".join(lines[1:frontmatter_end])
        try:
            frontmatter_payload = yaml.safe_load(frontmatter_text) if frontmatter_text.strip() else None
        except yaml.YAMLError as exc:
            raise SkillParseError(f"Failed to parse frontmatter in {path}: {exc}") from exc

        if frontmatter_payload is None:
            frontmatter = None
        elif isinstance(frontmatter_payload, dict):
            frontmatter = frontmatter_payload
        else:
            raise SkillParseError(f"Frontmatter in {path} must be a YAML mapping")

        body_lines = lines[frontmatter_end + 1 :]

    fields: list[DocumentField] = []
    keys: list[DocumentKey] = []

    body_start = len(lines) - len(body_lines) + 1
    active_fence_char: str | None = None
    for offset, line in enumerate(body_lines):
        index = body_start + offset
        stripped = line.strip()
        fence_char = _extract_fence_char(stripped)
        in_code_block = active_fence_char is not None
        if fence_char is not None:
            in_code_block = True
            if active_fence_char is None:
                active_fence_char = fence_char
            elif fence_char == active_fence_char:
                active_fence_char = None
        if not stripped:
            continue
        key = _extract_key_from_line(stripped)
        if in_code_block:
            source = "code_block"
        elif key is not None:
            source = "config_line"
        else:
            source = "prose"
        fields.append(
            DocumentField(
                path=("line", str(index)),
                value=stripped,
                line=index,
                snippet=_line_snippet(stripped),
                in_code_block=in_code_block,
                field_source=source,
            )
        )
        if key:
            keys.append(
                DocumentKey(
                    path=("line", str(index)),
                    key=key,
                    line=index,
                    snippet=_line_snippet(stripped),
                )
            )

    return ParsedSkillDocument(
        file_path=path,
        raw_text=raw_text,
        frontmatter=frontmatter,
        body="\n".join(body_lines).strip(),
        fields=tuple(fields),
        keys=tuple(keys),
    )


def _find_frontmatter_end(lines: list[str]) -> int | None:
    for index in range(1, len(lines)):
        if lines[index].strip() in {FRONTMATTER_DELIMITER, FRONTMATTER_ALT_DELIMITER}:
            return index
    return None


def _extract_key_from_line(line: str) -> str | None:
    match = KEY_LINE_PATTERN.match(line)
    if not match:
        return None
    key = match.group(1).strip()
    if not key:
        return None
    if key.lower() in KEY_LINE_EXCLUDE:
        return None
    return key


def _line_snippet(line: str) -> str:
    return line[:SNIPPET_MAX_LENGTH]


def _extract_fence_char(line: str) -> str | None:
    match = FENCED_CODE_BLOCK_PATTERN.match(line)
    if not match:
        return None
    marker = match.group(1)
    if len(marker) < 3:
        return None
    return marker[0]
