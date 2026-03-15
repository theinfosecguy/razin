"""Unicode bidirectional control character detection operation for DSL rules."""

from __future__ import annotations

from typing import Any

from razin.constants.detectors import (
    BIDI_CHAR_NAMES,
    BIDI_CONTROL_CHARS,
    BIDI_OVERRIDE_CHARS,
    BIDI_OVERRIDE_CLOSER,
)
from razin.model import Evidence, FindingCandidate
from razin.types.dsl import EvalContext


def run_bidi_control_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan raw text for Unicode bidi control characters (Trojan Source risk)."""
    raw = ctx.parsed.raw_text
    signals: list[str] = []
    evidence_line: int | None = None
    evidence_snippet: str = ""
    active_fence_char: str | None = None
    score = base_score
    override_depth = 0

    for line_num, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        active_fence_char = _update_fence_state(stripped, active_fence_char)
        in_code_fence = active_fence_char is not None

        line_bidi = _find_bidi_chars_in_line(line)
        if not line_bidi:
            continue

        char_labels = [f"U+{cp:04X} {BIDI_CHAR_NAMES.get(cp, '?')}" for cp in line_bidi]
        signals.append(f"line {line_num}: {', '.join(char_labels)}")

        if evidence_line is None:
            evidence_line = line_num
            evidence_snippet = _render_evidence_snippet(line, line_bidi)

        if in_code_fence and score < base_score + 7:
            score = min(base_score + 7, 100)

        override_depth = _update_override_depth(line, override_depth)

    min_signals: int = match_config.get("min_signals", 1)
    if len(signals) < min_signals:
        return []

    if override_depth > 0:
        score = min(score + 5, 100)

    description = metadata.get("description", "")
    if signals:
        summary = "; ".join(signals[:5])
        if len(signals) > 5:
            summary += f" (+{len(signals) - 5} more)"
        description = f"{description} Detected: {summary}."

    return [
        FindingCandidate(
            rule_id="",
            score=score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=description,
            evidence=Evidence(
                path=str(ctx.parsed.file_path),
                line=evidence_line or 1,
                snippet=evidence_snippet[:200],
            ),
            recommendation=metadata["recommendation"],
        )
    ]


def _find_bidi_chars_in_line(line: str) -> list[int]:
    """Return codepoints of bidi control characters found in the line."""
    found: list[int] = []
    seen: set[int] = set()
    for ch in line:
        cp = ord(ch)
        if cp in BIDI_CONTROL_CHARS and cp not in seen:
            found.append(cp)
            seen.add(cp)
    return found


def _has_unpaired_override(line: str) -> bool:
    """Return True if the line contains an override (LRO/RLO) without a matching PDF."""
    override_count = 0
    for ch in line:
        cp = ord(ch)
        if cp in BIDI_OVERRIDE_CHARS:
            override_count += 1
        elif cp == BIDI_OVERRIDE_CLOSER and override_count > 0:
            override_count -= 1
    return override_count > 0


def _update_override_depth(line: str, current_depth: int) -> int:
    """Update running override depth by scanning a line for LRO/RLO opens and PDF closes."""
    depth = current_depth
    for ch in line:
        cp = ord(ch)
        if cp in BIDI_OVERRIDE_CHARS:
            depth += 1
        elif cp == BIDI_OVERRIDE_CLOSER and depth > 0:
            depth -= 1
    return depth


def _render_evidence_snippet(line: str, bidi_codepoints: list[int]) -> str:
    """Render a line with bidi chars replaced by visible [U+XXXX NAME] markers."""
    bidi_set = set(bidi_codepoints)
    parts: list[str] = []
    for ch in line:
        cp = ord(ch)
        if cp in bidi_set:
            name = BIDI_CHAR_NAMES.get(cp, "?")
            parts.append(f"[U+{cp:04X} {name}]")
        else:
            parts.append(ch)
    return "".join(parts).strip()


def _update_fence_state(stripped: str, active_fence_char: str | None) -> str | None:
    """Track fenced code block state, matching opener/closer by marker character."""
    for marker_char in ("`", "~"):
        if stripped.startswith(marker_char * 3):
            if active_fence_char is None:
                return marker_char
            if marker_char == active_fence_char:
                return None
            return active_fence_char
    return active_fence_char
