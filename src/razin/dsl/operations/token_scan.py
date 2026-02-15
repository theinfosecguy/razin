"""Tool token scanning operation for DSL rules."""

from __future__ import annotations

import re
from typing import Any

from razin.constants.docs import (
    DEFAULT_SERVICE_TOOL_PREFIXES,
    SERVICE_TOOL_MIN_TOTAL_LENGTH,
    SERVICE_TOOL_TOKEN_PATTERN,
    TOOL_CONSOLIDATION_MAX_SCORE,
    TOOL_CONSOLIDATION_TOP_N,
    TOOL_TIER_DESTRUCTIVE_BONUS,
    TOOL_TIER_WRITE_BONUS,
    TOOL_TOKEN_PATTERN,
)
from razin.detectors.common import field_evidence
from razin.dsl.context import EvalContext
from razin.model import Evidence, FindingCandidate


def run_token_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Find uppercase tool tokens via prefixes and emit one consolidated finding."""
    prefix_source: str = match_config.get("prefix_source", "config.tool_prefixes")
    token_pattern_str: str | None = match_config.get("token_pattern")
    token_re = re.compile(token_pattern_str) if token_pattern_str else TOOL_TOKEN_PATTERN
    scan_service_tokens: bool = bool(match_config.get("scan_service_tokens", False))
    service_pattern_str: str | None = match_config.get("service_token_pattern")
    service_token_re = re.compile(service_pattern_str) if service_pattern_str else SERVICE_TOOL_TOKEN_PATTERN
    service_min_total_length = int(match_config.get("service_min_total_length", SERVICE_TOOL_MIN_TOTAL_LENGTH))
    service_min_segments = int(match_config.get("service_min_segments", 3))

    if prefix_source == "config.tool_prefixes":
        prefixes = tuple(p.upper() for p in ctx.config.tool_prefixes if p)
    else:
        prefixes = tuple(str(prefix).upper() for prefix in match_config.get("prefixes", []) if str(prefix).strip())

    if not prefixes and not scan_service_tokens:
        return []

    service_prefixes = _service_prefixes(match_config)

    seen_tokens: set[str] = set()
    first_evidence: Evidence | None = None
    for field in ctx.parsed.fields:
        for token in token_re.findall(field.value):
            if token in seen_tokens:
                continue
            matches_prefix = token.startswith(prefixes)
            matches_service = scan_service_tokens and _is_service_tool_token(
                token=token,
                token_re=service_token_re,
                service_prefixes=service_prefixes,
                min_total_length=service_min_total_length,
                min_segments=service_min_segments,
            )
            if not matches_prefix and not matches_service:
                continue
            seen_tokens.add(token)
            if first_evidence is None:
                first_evidence = field_evidence(ctx.parsed, field)

    if not seen_tokens:
        return []

    destructive_kw = ctx.config.tool_tier_keywords.destructive
    write_kw = ctx.config.tool_tier_keywords.write

    destructive_tokens: list[str] = []
    write_tokens: list[str] = []
    read_tokens: list[str] = []
    for token in sorted(seen_tokens):
        tier = _classify_token_tier(token, destructive_kw, write_kw)
        if tier == "destructive":
            destructive_tokens.append(token)
        elif tier == "write":
            write_tokens.append(token)
        else:
            read_tokens.append(token)

    score = _compute_consolidated_score(
        base_score=base_score,
        total=len(seen_tokens),
        destructive_count=len(destructive_tokens),
        write_count=len(write_tokens),
    )

    description = _build_consolidated_description(
        total=len(seen_tokens),
        destructive_tokens=destructive_tokens,
        write_tokens=write_tokens,
        read_tokens=read_tokens,
    )

    top_n = TOOL_CONSOLIDATION_TOP_N
    sorted_tokens = sorted(seen_tokens)
    snippet_tokens = sorted_tokens[:top_n]
    snippet = ", ".join(snippet_tokens)
    if len(sorted_tokens) > top_n:
        snippet += f" (+{len(sorted_tokens) - top_n} more)"

    assert first_evidence is not None
    evidence = Evidence(
        path=first_evidence.path,
        line=first_evidence.line,
        snippet=snippet,
    )

    return [
        FindingCandidate(
            rule_id="",
            score=score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=description,
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
    ]


def _classify_token_tier(
    token: str,
    destructive_keywords: tuple[str, ...],
    write_keywords: tuple[str, ...],
) -> str:
    """Classify a tool token into destructive, write, or read tier."""
    segments = token.split("_")
    for segment in segments:
        if segment in destructive_keywords:
            return "destructive"
    for segment in segments:
        if segment in write_keywords:
            return "write"
    return "read"


def _compute_consolidated_score(
    *,
    base_score: int,
    total: int,
    destructive_count: int,
    write_count: int,
) -> int:
    """Compute a consolidated score that scales with token count and tiers."""
    score = base_score + min(total, 10) * 2
    score += destructive_count * TOOL_TIER_DESTRUCTIVE_BONUS
    score += write_count * TOOL_TIER_WRITE_BONUS
    return min(score, TOOL_CONSOLIDATION_MAX_SCORE)


def _build_consolidated_description(
    *,
    total: int,
    destructive_tokens: list[str],
    write_tokens: list[str],
    read_tokens: list[str],
) -> str:
    """Build a human-readable description with tier breakdown."""
    parts: list[str] = [f"Skill references {total} tool invocation token{'s' if total != 1 else ''}."]
    tier_parts: list[str] = []
    if destructive_tokens:
        tier_parts.append(f"{len(destructive_tokens)} destructive")
    if write_tokens:
        tier_parts.append(f"{len(write_tokens)} write")
    if read_tokens:
        tier_parts.append(f"{len(read_tokens)} read")
    if tier_parts:
        parts.append(f"Tiers: {', '.join(tier_parts)}.")
    return " ".join(parts)


def _service_prefixes(match_config: dict[str, Any]) -> tuple[str, ...]:
    """Resolve service prefixes from match config or defaults."""
    raw_prefixes = match_config.get("service_prefixes")
    if not isinstance(raw_prefixes, (list, tuple)):
        raw_prefixes = list(DEFAULT_SERVICE_TOOL_PREFIXES)
    prefixes: list[str] = []
    for value in raw_prefixes:
        if not isinstance(value, str):
            continue
        normalized = value.strip().upper()
        if normalized:
            prefixes.append(normalized)
    return tuple(prefixes)


def _is_service_tool_token(
    *,
    token: str,
    token_re: re.Pattern[str],
    service_prefixes: tuple[str, ...],
    min_total_length: int,
    min_segments: int,
) -> bool:
    """Return True when *token* matches the service tool token pattern."""
    if len(token) < min_total_length:
        return False
    if not token_re.fullmatch(token):
        return False
    segments = token.split("_")
    if len(segments) < min_segments:
        return False
    if service_prefixes:
        return segments[0] in service_prefixes
    return True
