"""Obfuscated payload decoding and injection-hint detection operation for DSL rules."""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Any

from razin.constants.detectors import (
    OBFUSCATED_BASE64_MIN_LENGTH,
    OBFUSCATED_BASE64_RE,
    OBFUSCATED_HEX_MIN_LENGTH,
    OBFUSCATED_HEX_RE,
    OBFUSCATED_INJECTION_HINTS,
    OBFUSCATED_MAX_CANDIDATES_PER_FILE,
    OBFUSCATED_MAX_DECODE_LENGTH,
    OBFUSCATED_UNICODE_ESCAPE_RE,
)
from razin.model import Evidence, FindingCandidate
from razin.types.dsl import EvalContext

logger = logging.getLogger(__name__)


def run_payload_decode_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan raw text for encoded blocks, decode them, and check for injection hints."""
    raw = ctx.parsed.raw_text
    max_candidates: int = match_config.get("max_candidates", OBFUSCATED_MAX_CANDIDATES_PER_FILE)
    max_decode_len: int = match_config.get("max_decode_length", OBFUSCATED_MAX_DECODE_LENGTH)
    injection_hints: tuple[str, ...] = tuple(match_config.get("injection_hints", OBFUSCATED_INJECTION_HINTS))
    min_hint_matches: int = match_config.get("min_hint_matches", 1)

    candidates: list[_DecodedCandidate] = []
    candidates.extend(_extract_base64_candidates(raw, max_decode_len))
    candidates.extend(_extract_hex_candidates(raw, max_decode_len))
    candidates.extend(_extract_unicode_escape_candidates(raw, max_decode_len))

    if len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]

    findings: list[FindingCandidate] = []
    seen_lines: set[int] = set()

    for candidate in candidates:
        matched_hints = _match_injection_hints(candidate.decoded, injection_hints)
        if len(matched_hints) < min_hint_matches:
            continue

        if candidate.line in seen_lines:
            continue
        seen_lines.add(candidate.line)

        snippet = _render_evidence_snippet(candidate.encoding, candidate.encoded_preview, matched_hints)
        hint_summary = "; ".join(matched_hints[:3])
        if len(matched_hints) > 3:
            hint_summary += f" (+{len(matched_hints) - 3} more)"

        description = metadata.get("description", "")
        description = (
            f"{description} "
            f"{candidate.encoding}-encoded block on line {candidate.line} "
            f"decodes to injection hints: {hint_summary}."
        )

        findings.append(
            FindingCandidate(
                rule_id="",
                score=base_score,
                confidence=metadata["confidence"],
                title=metadata["title"],
                description=description,
                evidence=Evidence(
                    path=str(ctx.parsed.file_path),
                    line=candidate.line,
                    snippet=snippet[:200],
                ),
                recommendation=metadata["recommendation"],
            )
        )

    return findings


class _DecodedCandidate:
    """Internal container for a decoded payload candidate."""

    __slots__ = ("encoding", "line", "encoded_preview", "decoded")

    def __init__(self, encoding: str, line: int, encoded_preview: str, decoded: str) -> None:
        self.encoding = encoding
        self.line = line
        self.encoded_preview = encoded_preview
        self.decoded = decoded


def _line_number_at_offset(text: str, offset: int) -> int:
    """Return the 1-based line number for a character offset in text."""
    return text[:offset].count("\n") + 1


def _extract_base64_candidates(text: str, max_decode_len: int) -> list[_DecodedCandidate]:
    """Find base64-like blocks in text and attempt decoding."""
    results: list[_DecodedCandidate] = []
    for match in OBFUSCATED_BASE64_RE.finditer(text):
        raw_match = match.group(0)
        if len(raw_match) < OBFUSCATED_BASE64_MIN_LENGTH:
            continue
        decoded = _try_base64_decode(raw_match, max_decode_len)
        if decoded is None:
            continue
        line = _line_number_at_offset(text, match.start())
        results.append(
            _DecodedCandidate(
                encoding="base64",
                line=line,
                encoded_preview=raw_match[:60],
                decoded=decoded,
            )
        )
    return results


def _extract_hex_candidates(text: str, max_decode_len: int) -> list[_DecodedCandidate]:
    """Find hex-encoded blocks in text and attempt decoding."""
    results: list[_DecodedCandidate] = []
    for match in OBFUSCATED_HEX_RE.finditer(text):
        raw_match = match.group(0)
        hex_body = raw_match.removeprefix("0x")
        if len(hex_body) < OBFUSCATED_HEX_MIN_LENGTH:
            continue
        decoded = _try_hex_decode(hex_body, max_decode_len)
        if decoded is None:
            continue
        line = _line_number_at_offset(text, match.start())
        results.append(
            _DecodedCandidate(
                encoding="hex",
                line=line,
                encoded_preview=raw_match[:60],
                decoded=decoded,
            )
        )
    return results


def _extract_unicode_escape_candidates(text: str, max_decode_len: int) -> list[_DecodedCandidate]:
    """Find unicode escape sequences in text and attempt decoding."""
    results: list[_DecodedCandidate] = []
    for match in OBFUSCATED_UNICODE_ESCAPE_RE.finditer(text):
        raw_match = match.group(0)
        decoded = _try_unicode_escape_decode(raw_match, max_decode_len)
        if decoded is None:
            continue
        line = _line_number_at_offset(text, match.start())
        results.append(
            _DecodedCandidate(
                encoding="unicode-escape",
                line=line,
                encoded_preview=raw_match[:60],
                decoded=decoded,
            )
        )
    return results


def _try_base64_decode(value: str, max_len: int) -> str | None:
    """Attempt base64 decoding; return decoded UTF-8 text or None."""
    try:
        padded = value + "=" * (-len(value) % 4)
        raw_bytes = base64.b64decode(padded, validate=True)
        if len(raw_bytes) > max_len:
            return None
        decoded = raw_bytes.decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not _looks_like_text(decoded):
        return None
    return decoded


def _try_hex_decode(hex_str: str, max_len: int) -> str | None:
    """Attempt hex decoding; return decoded UTF-8 text or None."""
    try:
        raw_bytes = bytes.fromhex(hex_str)
        if len(raw_bytes) > max_len:
            return None
        decoded = raw_bytes.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if not _looks_like_text(decoded):
        return None
    return decoded


def _try_unicode_escape_decode(value: str, max_len: int) -> str | None:
    """Attempt unicode escape decoding; return decoded text or None."""
    try:
        decoded = value.encode("utf-8").decode("unicode_escape")
        if len(decoded) > max_len:
            return None
    except (ValueError, UnicodeDecodeError):
        return None
    if not _looks_like_text(decoded):
        return None
    return decoded


def _looks_like_text(decoded: str) -> bool:
    """Return True if decoded content looks like readable text (not binary noise)."""
    if not decoded or len(decoded) < 4:
        return False
    printable_count = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\r\t")
    return (printable_count / len(decoded)) >= 0.7


def _match_injection_hints(decoded: str, hints: tuple[str, ...]) -> list[str]:
    """Return injection hint phrases found in the decoded text."""
    lowered = decoded.lower()
    return [hint for hint in hints if hint in lowered]


def _render_evidence_snippet(encoding: str, encoded_preview: str, matched_hints: list[str]) -> str:
    """Render a human-readable evidence snippet for the finding."""
    hint_preview = ", ".join(matched_hints[:2])
    return f"{encoding}: {encoded_preview}... decodes to [{hint_preview}]"
