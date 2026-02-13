"""File discovery and skill naming helpers."""

from __future__ import annotations

from pathlib import Path

from razin.constants.discovery import SKILL_MARKDOWN_FILENAME
from razin.utils import sanitize_output_name


def discover_skill_files(root: Path, skill_globs: tuple[str, ...], max_file_mb: int) -> list[Path]:
    """Discover SKILL.md files by configured glob patterns."""
    discovered: set[Path] = set()
    size_limit_bytes = max_file_mb * 1024 * 1024

    for pattern in skill_globs:
        for path in root.glob(pattern):
            if not path.is_file() or path.name != SKILL_MARKDOWN_FILENAME:
                continue
            try:
                if path.stat().st_size > size_limit_bytes:
                    continue
            except OSError:
                continue
            discovered.add(path.resolve())

    return sorted(discovered, key=lambda path: path.relative_to(root.resolve()).as_posix())


def derive_skill_name(file_path: Path, root: Path, *, declared_name: str | None = None) -> str:
    """Derive a stable output skill name for a discovered SKILL.md file."""
    root = root.resolve()
    file_path = file_path.resolve()

    if declared_name:
        return sanitize_skill_name(declared_name)

    skill_folder = _nearest_skill_folder_name(file_path)
    if skill_folder:
        return sanitize_skill_name(skill_folder)

    return sanitize_skill_name(_fallback_relative_name(file_path, root))


def sanitize_skill_name(raw_name: str) -> str:
    """Normalize skill name for deterministic output paths."""
    return sanitize_output_name(raw_name)


def _nearest_skill_folder_name(file_path: Path) -> str | None:
    if file_path.name == SKILL_MARKDOWN_FILENAME:
        return file_path.parent.name
    return None


def _fallback_relative_name(file_path: Path, root: Path) -> str:
    try:
        relative = file_path.relative_to(root)
        candidate = relative.with_suffix("").as_posix().replace("/", "-")
        return candidate
    except ValueError:
        return file_path.stem
