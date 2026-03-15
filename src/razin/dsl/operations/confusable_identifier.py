"""Extended confusable identifier detection operation for DSL rules."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from razin.constants.detectors import (
    CONFUSABLE_FRONTMATTER_KEYS,
    CONFUSABLE_IDENTIFIER_MIN_LENGTH,
    CONFUSABLE_IDENTIFIER_TOKEN_RE,
    HOMOGLYPH_CONFUSABLE_RANGES,
    URL_PATTERN,
)
from razin.dsl.operations.shared import flatten_frontmatter
from razin.model import Evidence, FindingCandidate
from razin.types.dsl import EvalContext


def run_confusable_identifier_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan skill content for mixed-script confusable identifiers across multiple surfaces."""
    min_length: int = match_config.get("min_length", CONFUSABLE_IDENTIFIER_MIN_LENGTH)
    fm_keys: frozenset[str] = frozenset(match_config.get("frontmatter_keys", CONFUSABLE_FRONTMATTER_KEYS))

    signals: list[_ConfusableSignal] = []
    seen: set[str] = set()

    body_start_line = _compute_body_start_line(ctx.parsed.raw_text)

    _scan_frontmatter(ctx, fm_keys, min_length, signals, seen)
    _scan_body_identifiers(ctx.parsed.body, body_start_line, min_length, signals, seen)
    _scan_url_hostnames(ctx.parsed.body, body_start_line, signals, seen)

    min_signals: int = match_config.get("min_signals", 1)
    if len(signals) < min_signals:
        return []

    first_signal = signals[0]
    summary = "; ".join(s.label for s in signals[:5])
    if len(signals) > 5:
        summary += f" (+{len(signals) - 5} more)"

    description = metadata.get("description", "")
    description = f"{description} Detected: {summary}."

    score = base_score
    if any(s.context == "frontmatter" for s in signals):
        score = min(score + 5, 100)

    return [
        FindingCandidate(
            rule_id="",
            score=score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=description,
            evidence=Evidence(
                path=str(ctx.parsed.file_path),
                line=first_signal.line,
                snippet=first_signal.snippet[:200],
            ),
            recommendation=metadata["recommendation"],
        )
    ]


@dataclass(frozen=True, slots=True)
class _ConfusableSignal:
    """Internal container for a confusable identifier detection signal."""

    context: str
    token: str
    label: str
    line: int
    snippet: str


def _scan_frontmatter(
    ctx: EvalContext,
    fm_keys: frozenset[str],
    min_length: int,
    signals: list[_ConfusableSignal],
    seen: set[str],
) -> None:
    """Scan frontmatter values for confusable identifiers."""
    if not isinstance(ctx.parsed.frontmatter, dict):
        return

    for dotted_key, value in flatten_frontmatter(ctx.parsed.frontmatter):
        leaf = dotted_key.split(".")[-1].lower()
        if leaf not in fm_keys:
            continue

        for token in CONFUSABLE_IDENTIFIER_TOKEN_RE.findall(value):
            if len(token) < min_length or token in seen:
                continue
            confusables = _find_mixed_script_confusables(token)
            if not confusables:
                continue
            seen.add(token)
            chars_desc = ", ".join(sorted(confusables))
            line = _frontmatter_token_line(ctx.parsed.raw_text, token)
            snippet = _render_confusable_snippet(token, confusables)
            signals.append(
                _ConfusableSignal(
                    context="frontmatter",
                    token=token,
                    label=f"frontmatter '{dotted_key}': confusable '{token}' ({chars_desc})",
                    line=line,
                    snippet=snippet,
                )
            )


def _scan_body_identifiers(
    body_text: str,
    body_start_line: int,
    min_length: int,
    signals: list[_ConfusableSignal],
    seen: set[str],
) -> None:
    """Scan body text (excluding frontmatter) for identifier-like tokens with mixed-script confusables."""
    for offset, line in enumerate(body_text.splitlines()):
        line_num = body_start_line + offset
        for token in CONFUSABLE_IDENTIFIER_TOKEN_RE.findall(line):
            if len(token) < min_length or token in seen:
                continue
            confusables = _find_mixed_script_confusables(token)
            if not confusables:
                continue
            seen.add(token)
            chars_desc = ", ".join(sorted(confusables))
            snippet = _render_confusable_snippet(token, confusables)
            signals.append(
                _ConfusableSignal(
                    context="body",
                    token=token,
                    label=f"body line {line_num}: confusable '{token}' ({chars_desc})",
                    line=line_num,
                    snippet=snippet,
                )
            )


def _scan_url_hostnames(
    body_text: str,
    body_start_line: int,
    signals: list[_ConfusableSignal],
    seen: set[str],
) -> None:
    """Scan body text URL hostnames for confusable characters."""
    for match in URL_PATTERN.finditer(body_text):
        url = match.group(0)
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        if not host or host in seen:
            continue
        confusables = _find_mixed_script_confusables(host)
        if not confusables:
            continue
        seen.add(host)
        chars_desc = ", ".join(sorted(confusables))
        line = body_text[: match.start()].count("\n") + body_start_line
        snippet = _render_confusable_snippet(host, confusables)
        signals.append(
            _ConfusableSignal(
                context="url",
                token=host,
                label=f"URL hostname: confusable '{host}' ({chars_desc})",
                line=line,
                snippet=snippet,
            )
        )


def _find_mixed_script_confusables(token: str) -> set[str]:
    """Return confusable character names if token mixes ASCII with confusable-range chars."""
    found: set[str] = set()
    has_ascii = False
    has_confusable = False
    for ch in token:
        cp = ord(ch)
        if cp < 128:
            has_ascii = True
        else:
            for start, end in HOMOGLYPH_CONFUSABLE_RANGES:
                if start <= cp <= end:
                    has_confusable = True
                    name = unicodedata.name(ch, f"U+{cp:04X}")
                    found.add(name)
                    break
    if has_ascii and has_confusable:
        return found
    return set()


def _frontmatter_token_line(raw_text: str, token: str) -> int:
    """Return the 1-based line number where a token appears within the frontmatter block."""
    lines = raw_text.splitlines()
    in_frontmatter = False
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if idx == 1 and stripped == "---":
            in_frontmatter = True
            continue
        if in_frontmatter and stripped in ("---", "..."):
            break
        if in_frontmatter and token in line:
            return idx
    return 1


def _compute_body_start_line(raw_text: str) -> int:
    """Return the 1-based line number where the body begins (after closing frontmatter delimiter)."""
    lines = raw_text.splitlines()
    if not lines or lines[0].strip() != "---":
        return 1
    for idx in range(1, len(lines)):
        if lines[idx].strip() in ("---", "..."):
            return idx + 2
    return 1


def _render_confusable_snippet(token: str, confusable_names: set[str]) -> str:
    """Render a token with confusable chars annotated as [U+XXXX NAME]."""
    confusable_cps: set[int] = set()
    for ch in token:
        cp = ord(ch)
        for start, end in HOMOGLYPH_CONFUSABLE_RANGES:
            if start <= cp <= end:
                confusable_cps.add(cp)
                break

    parts: list[str] = []
    for ch in token:
        cp = ord(ch)
        if cp in confusable_cps:
            name = unicodedata.name(ch, f"U+{cp:04X}")
            parts.append(f"[U+{cp:04X} {name}]")
        else:
            parts.append(ch)
    return "".join(parts)
