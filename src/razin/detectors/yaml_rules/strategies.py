"""Strategy implementations for YAML-driven detectors.

Each strategy function takes parsed data, match config, metadata, and scoring
config, then returns a list of FindingCandidate objects. Strategies are the
Python predicates that YAML rules reference by name — they encapsulate the
complex logic that must remain in Python while accepting YAML-tunable parameters.
"""

from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import urlparse

from razin.config import RaisinConfig
from razin.constants.detectors import URL_PATTERN
from razin.detectors.common import (
    dedupe_candidates,
    extract_domain,
    field_evidence,
    is_allowlisted,
    normalize_url,
)
from razin.model import Evidence, FindingCandidate, ParsedSkillDocument

NEGATION_PREFIXES: tuple[str, ...] = (
    "no ",
    "not ",
    "without ",
    "don't need",
    "doesn't require",
    "not require",
    "not needed",
    "no need for",
)

MCP_PATH_TOKEN: str = "/mcp"


def run_url_domain_filter(
    *,
    parsed: ParsedSkillDocument,
    config: RaisinConfig,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Strategy: iterate fields, extract URLs, apply url_filter + domain_check predicates."""
    url_filter_name = match_config["url_filter"]
    domain_check_name = match_config["domain_check"]

    url_filter_fn = _URL_FILTERS.get(url_filter_name)
    domain_check_fn = _DOMAIN_CHECKS.get(domain_check_name)

    if url_filter_fn is None:
        raise ValueError(f"Unknown url_filter predicate: {url_filter_name!r}")
    if domain_check_fn is None:
        raise ValueError(f"Unknown domain_check predicate: {domain_check_name!r}")

    description_template = metadata.get("description_template", metadata.get("description", ""))
    findings: list[FindingCandidate] = []

    for field in parsed.fields:
        for raw_url in URL_PATTERN.findall(field.value):
            url = normalize_url(raw_url)
            dom = extract_domain(url)
            if not dom:
                continue

            if not url_filter_fn(url):
                continue

            if not domain_check_fn(dom, config):
                continue

            if "{url}" in description_template:
                description = description_template.format(url=url)
            else:
                description = description_template

            findings.append(
                FindingCandidate(
                    rule_id="",  # filled by caller
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=description,
                    evidence=field_evidence(parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )

    if do_dedupe:
        findings = dedupe_candidates(findings)
    return findings


def run_hint_count(
    *,
    parsed: ParsedSkillDocument,
    config: RaisinConfig,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Strategy: count strong/weak hints in raw text, require thresholds."""
    strong_hints: list[str] = match_config.get("strong_hints", [])
    weak_hints: list[str] = match_config.get("weak_hints", [])
    min_hint_count: int = match_config.get("min_hint_count", 2)
    require_strong: bool = match_config.get("require_strong", False)
    negation_aware: bool = match_config.get("negation_aware", False)

    lowered = parsed.raw_text.lower()

    if negation_aware:
        strong_matches = [h for h in strong_hints if h in lowered and not _hint_is_negated(lowered, h)]
        weak_matches = [h for h in weak_hints if h in lowered and not _hint_is_negated(lowered, h)]
    else:
        strong_matches = [h for h in strong_hints if h in lowered]
        weak_matches = [h for h in weak_hints if h in lowered]

    if require_strong and not strong_matches:
        return []

    all_matches = strong_matches + weak_matches
    if len(all_matches) < min_hint_count:
        return []

    best_hint = strong_matches[0] if strong_matches else all_matches[0]
    evidence = _best_evidence_for_hint(parsed, best_hint)

    return [
        FindingCandidate(
            rule_id="",  # filled by caller
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", metadata.get("description_template", "")),
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
    ]


def run_entropy_check(
    *,
    parsed: ParsedSkillDocument,
    config: RaisinConfig,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Strategy: check field values for length, entropy, and base64 patterns."""
    min_length: int = match_config.get("min_length", 80)
    min_entropy: float = match_config.get("min_entropy", 4.5)
    base64_pattern_str: str | None = match_config.get("base64_pattern")
    skip_prose: bool = match_config.get("skip_prose", False)
    prose_min_words: int = match_config.get("prose_min_words", 3)

    base64_re = re.compile(base64_pattern_str) if base64_pattern_str else None

    findings: list[FindingCandidate] = []

    for field in parsed.fields:
        value = field.value.strip()
        if len(value) < min_length:
            continue

        if skip_prose and _looks_like_prose(value, prose_min_words):
            continue

        entropy = _shannon_entropy(value)
        looks_base64 = bool(base64_re.match(value)) if base64_re else False

        if looks_base64 or entropy >= min_entropy:
            findings.append(
                FindingCandidate(
                    rule_id="",  # filled by caller
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=metadata.get("description", metadata.get("description_template", "")),
                    evidence=field_evidence(parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )

    if do_dedupe:
        findings = dedupe_candidates(findings)
    return findings


def _is_mcp_endpoint(url: str) -> bool:
    """Check if a URL path looks like an MCP endpoint."""
    cleaned = normalize_url(url)
    parsed = urlparse(cleaned)
    path = parsed.path.lower()
    return path == MCP_PATH_TOKEN or path.endswith(MCP_PATH_TOKEN) or f"{MCP_PATH_TOKEN}/" in path


def _not_mcp_allowlisted(domain: str, config: RaisinConfig) -> bool:
    """Return True when the domain is NOT on the MCP allowlist (i.e., should flag)."""
    return not is_allowlisted(domain, config.mcp_allowlist_domains)


_URL_FILTERS: dict[str, Any] = {
    "is_mcp_endpoint": _is_mcp_endpoint,
}

_DOMAIN_CHECKS: dict[str, Any] = {
    "not_mcp_allowlisted": _not_mcp_allowlisted,
}


def _shannon_entropy(value: str) -> float:
    """Compute Shannon entropy for a string value."""
    if not value:
        return 0.0

    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1

    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _looks_like_prose(value: str, min_words: int = 3) -> bool:
    """Return True when the value appears to be natural-language prose."""
    if " " not in value:
        return False
    words = value.split()
    return len(words) >= min_words


def _hint_is_negated(lowered_text: str, hint: str) -> bool:
    """Return True when every occurrence of hint in the text is negated."""
    if hint not in lowered_text:
        return True

    for line in lowered_text.splitlines():
        if hint not in line:
            continue
        negated = False
        for prefix in NEGATION_PREFIXES:
            idx = line.find(hint)
            window_start = max(0, idx - 30)
            window = line[window_start:idx]
            if prefix in window:
                negated = True
                break
        if not negated:
            return False
    return True


def _best_evidence_for_hint(parsed: ParsedSkillDocument, hint: str) -> Evidence:
    """Return evidence from the field that best matches hint."""
    hint_lower = hint.lower()
    for field in parsed.fields:
        line_lower = field.value.lower()
        if hint_lower not in line_lower:
            continue
        negated = False
        for prefix in NEGATION_PREFIXES:
            idx = line_lower.find(hint_lower)
            window_start = max(0, idx - 30)
            window = line_lower[window_start:idx]
            if prefix in window:
                negated = True
                break
        if not negated:
            return field_evidence(parsed, field)

    for field in parsed.fields:
        if hint.split()[0].lower() in field.value.lower():
            return field_evidence(parsed, field)

    raw_lines = parsed.raw_text.splitlines()
    first_line = raw_lines[0] if raw_lines else ""
    return Evidence(path=str(parsed.file_path), line=1, snippet=first_line[:200])


STRATEGY_REGISTRY: dict[str, Any] = {
    "url_domain_filter": run_url_domain_filter,
    "hint_count": run_hint_count,
    "entropy_check": run_entropy_check,
}
