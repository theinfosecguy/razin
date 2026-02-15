"""Bundled scripts detection operation for DSL rules."""

from __future__ import annotations

from typing import Any

from razin.constants.detectors import SCRIPT_FILE_EXTENSIONS
from razin.constants.parsing import SNIPPET_MAX_LENGTH
from razin.types.dsl import EvalContext
from razin.model import Evidence, FindingCandidate


def run_bundled_scripts_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan file system for executable scripts alongside SKILL.md."""
    extensions_list: list[str] = match_config.get("extensions", [])
    extensions = frozenset(extensions_list) if extensions_list else SCRIPT_FILE_EXTENSIONS

    skill_dir = ctx.parsed.file_path.parent
    bundled: list[str] = []

    for path in skill_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.name == "SKILL.md":
            continue
        if path.suffix.lower() in extensions:
            try:
                bundled.append(path.relative_to(skill_dir).as_posix())
            except ValueError:
                bundled.append(str(path))

    if not bundled:
        return []

    bundled_sorted = sorted(set(bundled))
    preview = ", ".join(bundled_sorted)
    snippet = preview[:SNIPPET_MAX_LENGTH]

    return [
        FindingCandidate(
            rule_id="",
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", ""),
            evidence=Evidence(
                path=str(ctx.parsed.file_path),
                line=None,
                snippet=snippet,
            ),
            recommendation=metadata["recommendation"],
        )
    ]
