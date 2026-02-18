"""Shared domain analysis helpers for init-from-scan and scan hints."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from razin.constants.detectors import URL_PATTERN
from razin.constants.init import (
    INIT_DESCRIPTION_QUOTED_VALUE_PATTERN,
    INIT_DOMAIN_TOKEN_PATTERN,
    INIT_FROM_SCAN_RULE_CONFIG_KEYS,
    INIT_FROM_SCAN_RULE_IDS,
    INIT_HINT_DOMINANCE_THRESHOLD,
    INIT_HINT_MIN_FINDINGS,
    INIT_NET_DOC_DOMAIN_RULE_ID,
)
from razin.detectors.common import extract_domain
from razin.model import Finding
from razin.types.init_config import DomainCount


def extract_domain_from_finding_text(*, rule_id: str, description: str, snippet: str) -> str | None:
    """Extract a normalized domain from finding description/snippet text."""
    snippet_domain = _extract_domain_from_urls(snippet)
    if snippet_domain:
        return snippet_domain

    description_url_domain = _extract_domain_from_urls(description)
    if description_url_domain:
        return description_url_domain

    if rule_id == INIT_NET_DOC_DOMAIN_RULE_ID:
        for token in INIT_DESCRIPTION_QUOTED_VALUE_PATTERN.findall(description):
            normalized = _normalize_domain_candidate(token)
            if normalized:
                return normalized

    return _extract_domain_token(snippet) or _extract_domain_token(description)


def sort_domain_counts(counts: Counter[str]) -> tuple[DomainCount, ...]:
    """Convert a domain counter into deterministic sorted ``DomainCount`` values."""
    sorted_pairs = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple(DomainCount(domain=domain, count=count) for domain, count in sorted_pairs)


def build_dominant_domain_hints(findings: Sequence[Finding]) -> tuple[str, ...]:
    """Return actionable dominant-domain hint messages derived from scan findings."""
    hints: list[str] = []
    for rule_id in INIT_FROM_SCAN_RULE_IDS:
        matching = [finding for finding in findings if finding.rule_id == rule_id]
        total_findings = len(matching)
        if total_findings < INIT_HINT_MIN_FINDINGS:
            continue

        domain_counts: Counter[str] = Counter()
        for finding in matching:
            domain = extract_domain_from_finding_text(
                rule_id=finding.rule_id,
                description=finding.description,
                snippet=finding.evidence.snippet,
            )
            if domain:
                domain_counts[domain] += 1

        top = _top_domain(domain_counts)
        if top is None:
            continue
        domain, count = top
        if count / total_findings <= INIT_HINT_DOMINANCE_THRESHOLD:
            continue

        config_key = INIT_FROM_SCAN_RULE_CONFIG_KEYS[rule_id]
        hints.append(
            f"hint: {domain} appeared in {count}/{total_findings} {rule_id} findings; "
            f"consider {config_key} in razin.yaml"
        )

    return tuple(hints)


def _extract_domain_from_urls(text: str) -> str | None:
    """Extract the first domain found in URL-like tokens within text."""
    for raw_url in URL_PATTERN.findall(text):
        domain = extract_domain(raw_url)
        if domain:
            return domain
    return None


def _extract_domain_token(text: str) -> str | None:
    """Extract the first bare domain token from free-form text."""
    match = INIT_DOMAIN_TOKEN_PATTERN.search(text)
    if match is None:
        return None
    return match.group(0).lower()


def _normalize_domain_candidate(candidate: str) -> str | None:
    """Normalize a quoted candidate as URL/domain and return a domain when valid."""
    cleaned = candidate.strip().lower().rstrip(".,;:!?)")
    if not cleaned:
        return None
    domain_from_url = extract_domain(cleaned)
    if domain_from_url:
        return domain_from_url
    if INIT_DOMAIN_TOKEN_PATTERN.fullmatch(cleaned):
        return cleaned
    return None


def _top_domain(counts: Counter[str]) -> tuple[str, int] | None:
    """Return the most frequent domain, tie-breaking lexically."""
    if not counts:
        return None
    return min(counts.items(), key=lambda item: (-item[1], item[0]))
