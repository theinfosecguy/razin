"""Shared helpers used across multiple DSL operation modules."""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any

from razin.constants.detectors import (
    BRACKET_IPV6_PATTERN,
    IP_PATTERN,
    LOCAL_DEV_HOSTS,
    LOCAL_DEV_TLDS,
    PROSE_MIN_WORDS,
    RESERVED_EXAMPLE_DOMAINS,
    URL_PATTERN,
)
from razin.constants.docs import NEGATION_PREFIXES
from razin.constants.naming import NON_ALNUM_DASH_PATTERN
from razin.detectors.common import extract_domain, field_evidence
from razin.model import Evidence, ParsedSkillDocument


def parse_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a string into an IP address object, or ``None`` on failure."""
    try:
        parsed = ipaddress.ip_address(value.strip().strip("[]"))
        if isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return parsed
        return None
    except ValueError:
        return None


def is_local_dev_host(domain: str) -> bool:
    """Return True for localhost, example domains, and local TLDs."""
    if domain in LOCAL_DEV_HOSTS:
        return True
    if domain in RESERVED_EXAMPLE_DOMAINS:
        return True
    return any(domain.endswith(tld) for tld in LOCAL_DEV_TLDS)


def extract_raw_ip_addresses(value: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Extract all IPv4/IPv6 addresses found in *value*."""
    extracted: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for url in URL_PATTERN.findall(value):
        domain = extract_domain(url)
        if not domain:
            continue
        parsed = parse_ip_address(domain)
        if parsed is not None:
            extracted.append(parsed)
    for ipv4 in IP_PATTERN.findall(value):
        parsed = parse_ip_address(ipv4)
        if parsed is not None:
            extracted.append(parsed)
    for ipv6 in BRACKET_IPV6_PATTERN.findall(value):
        parsed = parse_ip_address(ipv6)
        if parsed is not None:
            extracted.append(parsed)
    return extracted


def is_non_public_ip(ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for private, loopback, link-local, multicast, reserved, or unspecified IPs."""
    return (
        ip_addr.is_private
        or ip_addr.is_loopback
        or ip_addr.is_link_local
        or ip_addr.is_multicast
        or ip_addr.is_reserved
        or ip_addr.is_unspecified
    )


def shannon_entropy(value: str) -> float:
    """Compute the Shannon entropy of *value* in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def looks_like_prose(value: str, min_words: int = PROSE_MIN_WORDS) -> bool:
    """Return True when *value* looks like natural-language prose."""
    if " " not in value:
        return False
    return len(value.split()) >= min_words


def levenshtein_distance(left: str, right: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    prev = list(range(len(right) + 1))
    for i, cl in enumerate(left, 1):
        curr = [i]
        for j, cr in enumerate(right, 1):
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + (cl != cr)))
        prev = curr
    return prev[-1]


def hint_is_negated(lowered_text: str, hint: str) -> bool:
    """Return True when every occurrence of *hint* in *lowered_text* is negated."""
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


def best_evidence_for_hint(parsed: ParsedSkillDocument, hint: str) -> Evidence:
    """Return the best evidence for *hint*, preferring non-negated fields."""
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


def first_field_with_keyword(parsed: ParsedSkillDocument, keyword: str) -> Evidence:
    """Return evidence for the first field containing *keyword*."""
    kw_lower = keyword.lower()
    for field in parsed.fields:
        if kw_lower in field.value.lower():
            return field_evidence(parsed, field)
    raw_lines = parsed.raw_text.splitlines()
    first_line = raw_lines[0] if raw_lines else ""
    return Evidence(path=str(parsed.file_path), line=1, snippet=first_line[:200])


def declared_name(parsed: ParsedSkillDocument) -> str | None:
    """Extract the declared name from frontmatter, if present."""
    if isinstance(parsed.frontmatter, dict):
        name = parsed.frontmatter.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return None


def resolve_frontmatter_path(fm: dict[str, Any], dotted_path: str) -> Any:
    """Walk a dotted path through a nested frontmatter dict."""
    parts = dotted_path.split(".")
    current: Any = fm
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def is_empty_value(value: object) -> bool:
    """Return True for None, empty strings, and empty collections."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def format_template(template: str, **kwargs: str) -> str:
    """Safe template formatting - missing keys left as literal {key}."""
    result = template
    for key, value in kwargs.items():
        result = result.replace(f"{{{key}}}", value)
    return result


def tokenize_name(name: str) -> list[str]:
    """Split a skill/service name into lowercase tokens on non-alnum boundaries."""
    return [t for t in NON_ALNUM_DASH_PATTERN.split(name.lower()) if t]


def service_matches_name(service: str, name: str) -> bool:
    """Return True when *service* appears as a whole token in *name*."""
    return service in tokenize_name(name)


def keyword_in_text(keyword: str, text: str) -> bool:
    """Return True when *keyword* appears at word boundaries in *text*."""
    pattern = r"\b" + re.escape(keyword) + r"\b"
    return bool(re.search(pattern, text))
