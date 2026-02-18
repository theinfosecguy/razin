"""File discovery and skill naming helpers."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import yaml

from razin.constants.discovery import SKILL_MARKDOWN_FILENAME, SKILL_NAME_DISAMBIGUATION_HASH_LENGTH
from razin.utils import sanitize_output_name

logger = logging.getLogger(__name__)


def discover_skill_files(root: Path, skill_globs: tuple[str, ...], max_file_mb: int) -> list[Path]:
    """Discover SKILL.md files by configured glob patterns."""
    discovered: set[Path] = set()
    size_limit_bytes = max_file_mb * 1024 * 1024
    resolved_root = root.resolve()

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

    return sorted(discovered, key=lambda path: _stable_path_key(path, resolved_root))


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


def assign_unique_skill_names(
    skill_files: list[Path],
    root: Path,
) -> tuple[dict[Path, str], dict[str, tuple[Path, ...]]]:
    """Assign deterministic output names per skill file, disambiguating collisions.

    The base name follows ``derive_skill_name`` precedence. When multiple files
    resolve to the same base name, each is suffixed with a stable path-hash so
    findings and output directories remain one-to-one with files.
    """
    resolved_root = root.resolve()
    names_by_file: dict[Path, str] = {}
    paths_by_name: dict[str, list[Path]] = {}

    for path in skill_files:
        resolved_path = path.resolve()
        declared_name = _extract_frontmatter_name(resolved_path)
        base_name = derive_skill_name(resolved_path, resolved_root, declared_name=declared_name)
        names_by_file[resolved_path] = base_name
        paths_by_name.setdefault(base_name, []).append(resolved_path)

    collisions: dict[str, tuple[Path, ...]] = {}
    for base_name, paths in sorted(paths_by_name.items()):
        if len(paths) <= 1:
            continue
        sorted_paths = tuple(sorted(paths, key=lambda path: _stable_path_key(path, resolved_root)))
        collisions[base_name] = sorted_paths
        for path in sorted_paths:
            names_by_file[path] = f"{base_name}-{_stable_path_hash(path, resolved_root)}"

    return names_by_file, collisions


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


def _stable_path_key(file_path: Path, root: Path) -> str:
    """Return a deterministic path key relative to *root* when possible."""
    try:
        return file_path.relative_to(root).as_posix()
    except ValueError:
        return file_path.as_posix()


def _stable_path_hash(file_path: Path, root: Path) -> str:
    """Return a short deterministic hash for the skill file location."""
    seed = _stable_path_key(file_path, root).encode("utf-8")
    return hashlib.sha256(seed).hexdigest()[:SKILL_NAME_DISAMBIGUATION_HASH_LENGTH]


def collect_all_skill_names(skill_files: list[Path], root: Path) -> tuple[str, ...]:
    """Collect all skill names from discovered files via lightweight frontmatter parsing.

    For each SKILL.md, extracts the ``name`` field from YAML frontmatter
    (if present) and falls back to ``derive_skill_name()`` otherwise.
    Returns a sorted, deduplicated tuple of sanitized names.
    """
    names: set[str] = set()

    for path in skill_files:
        fm_name = _extract_frontmatter_name(path)
        if fm_name is None and not _is_readable_text(path):
            logger.debug("Pre-pass: skipping unreadable file from baseline: %s", path)
            continue
        derived = derive_skill_name(path, root, declared_name=fm_name)
        names.add(derived)
        if fm_name:
            sanitized_fm = sanitize_skill_name(fm_name)
            if sanitized_fm != derived:
                names.add(sanitized_fm)
        folder_derived = derive_skill_name(path, root, declared_name=None)
        if folder_derived != derived:
            names.add(folder_derived)

    return tuple(sorted(names))


def _is_readable_text(path: Path) -> bool:
    """Return True if *path* can be read as UTF-8 text."""
    try:
        path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return True


def _extract_frontmatter_name(path: Path) -> str | None:
    """Extract the ``name`` field from YAML frontmatter without full document parsing.

    Returns ``None`` on any read or parse failure, logging a warning.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Pre-pass: cannot read %s: %s", path, exc)
        return None

    text = text.lstrip("\ufeff")

    if not text.startswith("---"):
        return None

    end = text.find("\n---", 3)
    if end == -1:
        end = text.find("\n...", 3)
    if end == -1:
        return None

    try:
        fm = yaml.safe_load(text[3:end])
    except yaml.YAMLError as exc:
        logger.warning("Pre-pass: malformed YAML frontmatter in %s: %s", path, exc)
        return None

    if isinstance(fm, dict):
        name = fm.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()

    return None
