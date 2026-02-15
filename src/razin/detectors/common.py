"""Shared helpers for detector implementations."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from razin.model import DocumentField, Evidence, FindingCandidate, ParsedSkillDocument

# Characters commonly appended by markdown syntax that are not valid URL endings.
_TRAILING_PUNCT_RE = re.compile(r"[)`*.,;:!?\]]+$")


def normalize_url(url: str) -> str:
    """Strip trailing markdown punctuation from an extracted URL."""
    return _TRAILING_PUNCT_RE.sub("", url)


def field_evidence(parsed: ParsedSkillDocument, field: DocumentField) -> Evidence:
    """Build evidence from a parsed document field."""
    return Evidence(path=str(parsed.file_path), line=field.line, snippet=field.snippet)


def extract_domain(url: str) -> str | None:
    """Extract and normalize hostname from a URL string."""
    cleaned = normalize_url(url)
    parsed = urlparse(cleaned)
    host = parsed.hostname
    if not host:
        return None
    return host.lower().strip()


def is_allowlisted(domain: str, allowlist: tuple[str, ...], *, strict: bool = False) -> bool:
    """Return True when a domain is allowlisted.

    When *strict* is False (default), subdomains of allowlisted domains also
    match (e.g. ``docs.composio.dev`` matches ``composio.dev``).  When *strict*
    is True, only exact domain matches are considered.
    """
    if not allowlist:
        return False
    if strict:
        return domain in allowlist
    return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist)


def is_denylisted(domain: str, denylist: tuple[str, ...]) -> bool:
    """Return True when a domain or subdomain is denylisted."""
    if not denylist:
        return False
    if "*" in denylist:
        return True
    return any(domain == denied or domain.endswith(f".{denied}") for denied in denylist)


def dedupe_candidates(candidates: list[FindingCandidate]) -> list[FindingCandidate]:
    """Drop duplicate candidates sharing rule, location, and description."""
    seen: set[tuple[str, str, int | None, str]] = set()
    deduped: list[FindingCandidate] = []

    for candidate in candidates:
        key = (
            candidate.rule_id,
            candidate.evidence.path,
            candidate.evidence.line,
            candidate.description,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)

    return deduped
