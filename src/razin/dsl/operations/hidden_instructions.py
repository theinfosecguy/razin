"""Hidden instruction detection operation for DSL rules."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from razin.dsl.context import EvalContext
from razin.model import Evidence, FindingCandidate


def run_hidden_instruction_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan raw text for invisible characters, suspicious HTML comments, and homoglyphs."""
    from razin.constants.detectors import (
        EMBEDDED_BOM_CODEPOINT,
        HIDDEN_INSTRUCTION_PHRASES,
        HOMOGLYPH_CONFUSABLE_RANGES,
        HTML_COMMENT_PATTERN,
        ZERO_WIDTH_CHARS,
    )

    raw = ctx.parsed.raw_text
    signals: list[str] = []
    evidence_line: int | None = None
    evidence_snippet: str = ""

    zwc_found = _detect_zero_width_chars(raw, ZERO_WIDTH_CHARS)
    if zwc_found:
        names = ", ".join(sorted(zwc_found))
        signals.append(f"zero-width characters ({names})")
        evidence_line, evidence_snippet = _zwc_evidence(raw, ZERO_WIDTH_CHARS)

    bom_found = _detect_embedded_bom(raw, EMBEDDED_BOM_CODEPOINT)
    if bom_found:
        signals.append("embedded BOM (U+FEFF) in body text")
        if evidence_line is None:
            evidence_line, evidence_snippet = _embedded_bom_evidence(raw, EMBEDDED_BOM_CODEPOINT)

    comment_signals = _detect_suspicious_html_comments(raw, HTML_COMMENT_PATTERN, HIDDEN_INSTRUCTION_PHRASES)
    if comment_signals:
        signals.extend(comment_signals)
        if evidence_line is None:
            evidence_line, evidence_snippet = _html_comment_evidence(
                raw, HTML_COMMENT_PATTERN, HIDDEN_INSTRUCTION_PHRASES
            )

    homoglyph_signals = _detect_homoglyphs(raw, HOMOGLYPH_CONFUSABLE_RANGES)
    if homoglyph_signals:
        signals.extend(homoglyph_signals)
        if evidence_line is None:
            evidence_line, evidence_snippet = _homoglyph_evidence(raw, HOMOGLYPH_CONFUSABLE_RANGES)

    min_signals: int = match_config.get("min_signals", 1)
    if len(signals) < min_signals:
        return []

    description = metadata.get("description", "")
    if signals:
        description = f"{description} Detected: {'; '.join(signals)}."

    return [
        FindingCandidate(
            rule_id="",
            score=base_score,
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


def _detect_zero_width_chars(text: str, chars: frozenset[int]) -> set[str]:
    """Return human-readable names for any zero-width characters found in text."""
    import unicodedata

    found: set[str] = set()
    for ch in text:
        if ord(ch) in chars:
            name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            found.add(name)
    return found


def _zwc_evidence(text: str, chars: frozenset[int]) -> tuple[int, str]:
    """Return (line_number, snippet) for the first zero-width character occurrence."""
    for line_num, line in enumerate(text.splitlines(), start=1):
        for ch in line:
            if ord(ch) in chars:
                return line_num, repr(line.strip())[:200]
    return 1, ""


def _detect_suspicious_html_comments(
    text: str,
    pattern: re.Pattern[str],
    phrases: tuple[str, ...],
) -> list[str]:
    """Return descriptions of HTML comments containing imperative injection phrases."""
    signals: list[str] = []
    for match in pattern.finditer(text):
        body = match.group(1).lower().strip()
        if not body:
            continue
        matched = [p for p in phrases if p in body]
        if matched:
            preview = body[:60].replace("\n", " ")
            signals.append(f"HTML comment with injection phrases: '{preview}'")
    return signals


def _html_comment_evidence(
    text: str,
    pattern: re.Pattern[str],
    phrases: tuple[str, ...],
) -> tuple[int, str]:
    """Return (line_number, snippet) for the first suspicious HTML comment."""
    for match in pattern.finditer(text):
        body = match.group(1).lower().strip()
        matched = [p for p in phrases if p in body]
        if matched:
            offset = match.start()
            line_num = text[:offset].count("\n") + 1
            snippet = match.group(0)[:200]
            return line_num, snippet
    return 1, ""


def _detect_embedded_bom(text: str, bom_cp: int) -> bool:
    """Return True if U+FEFF appears anywhere except byte-offset 0."""
    bom_char = chr(bom_cp)
    idx = text.find(bom_char, 1)
    return idx >= 1


def _embedded_bom_evidence(text: str, bom_cp: int) -> tuple[int, str]:
    """Return (line_number, snippet) for the first embedded BOM occurrence."""
    bom_char = chr(bom_cp)
    for line_num, line in enumerate(text.splitlines(), start=1):
        pos = line.find(bom_char)
        if pos >= 0:
            if line_num == 1 and pos == 0:
                continue
            return line_num, repr(line.strip())[:200]
    return 1, ""


def _detect_homoglyphs(
    text: str,
    confusable_ranges: tuple[tuple[int, int], ...],
) -> list[str]:
    """Detect mixed-script tokens and URLs containing confusable characters."""
    signals: list[str] = []
    seen: set[str] = set()

    for line in text.splitlines():
        for token in _extract_uppercase_tokens(line):
            confusables = _find_confusables_in_token(token, confusable_ranges)
            if confusables and token not in seen:
                seen.add(token)
                chars_desc = ", ".join(sorted(confusables))
                signals.append(f"confusable/homoglyph token '{token}' ({chars_desc})")

    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    for match in url_pattern.finditer(text):
        url = match.group(0)
        host = _extract_host(url)
        if host:
            confusables = _find_confusables_in_token(host, confusable_ranges)
            if confusables and host not in seen:
                seen.add(host)
                chars_desc = ", ".join(sorted(confusables))
                signals.append(f"confusable/homoglyph domain '{host}' ({chars_desc})")

    return signals


def _homoglyph_evidence(
    text: str,
    confusable_ranges: tuple[tuple[int, int], ...],
) -> tuple[int, str]:
    """Return (line_number, snippet) for the first homoglyph occurrence."""
    for line_num, line in enumerate(text.splitlines(), start=1):
        for token in _extract_uppercase_tokens(line):
            if _find_confusables_in_token(token, confusable_ranges):
                return line_num, line.strip()[:200]
        url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
        for match in url_pattern.finditer(line):
            host = _extract_host(match.group(0))
            if host and _find_confusables_in_token(host, confusable_ranges):
                return line_num, line.strip()[:200]
    return 1, ""


def _extract_uppercase_tokens(line: str) -> list[str]:
    """Extract uppercase token-like words (3+ chars, underscores allowed)."""
    return re.findall(
        r"\b[A-Z\u0370-\u03FF\u0400-\u04FF\u2100-\u214F\uFF00-\uFFEF]"
        r"[A-Z0-9_\u0370-\u03FF\u0400-\u04FF\u2100-\u214F\uFF00-\uFFEF]{2,}\b",
        line,
    )


def _find_confusables_in_token(
    token: str,
    confusable_ranges: tuple[tuple[int, int], ...],
) -> set[str]:
    """Return set of confusable character names found in a token."""
    import unicodedata

    found: set[str] = set()
    has_ascii = False
    has_non_ascii = False
    for ch in token:
        cp = ord(ch)
        if cp < 128:
            has_ascii = True
        else:
            for start, end in confusable_ranges:
                if start <= cp <= end:
                    has_non_ascii = True
                    name = unicodedata.name(ch, f"U+{cp:04X}")
                    found.add(name)
                    break
    if has_ascii and has_non_ascii:
        return found
    return set()


def _extract_host(url: str) -> str:
    """Extract hostname from a URL string."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""
