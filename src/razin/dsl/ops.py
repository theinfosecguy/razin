"""Audited operation registry for DSL v1.

Every operation callable is registered here. Only registered ops can be
invoked from YAML rules. No eval, no dynamic imports, no arbitrary callouts.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any
from urllib.parse import urlparse

from razin.constants.detectors import (
    BRACKET_IPV6_PATTERN,
    ENV_REF_PATTERN,
    IP_PATTERN,
    LOCAL_DEV_HOSTS,
    LOCAL_DEV_TLDS,
    RESERVED_EXAMPLE_DOMAINS,
    SCRIPT_FILE_EXTENSIONS,
    SECRET_PLACEHOLDER_VALUE_PATTERN,
    URL_PATTERN,
)
from razin.constants.docs import (
    DEFAULT_SERVICE_TOOL_PREFIXES,
    SERVICE_TOOL_MIN_TOTAL_LENGTH,
    SERVICE_TOOL_TOKEN_PATTERN,
    TOOL_TOKEN_PATTERN,
)
from razin.constants.parsing import SNIPPET_MAX_LENGTH
from razin.detectors.common import (
    dedupe_candidates,
    extract_domain,
    field_evidence,
    is_allowlisted,
    is_denylisted,
    normalize_url,
)
from razin.dsl.context import EvalContext
from razin.model import Evidence, FindingCandidate, ParsedSkillDocument
from razin.utils import normalize_similarity_name

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

_PROSE_MIN_WORDS_DEFAULT: int = 3

_NON_SECRET_ENV_OPERATORS: frozenset[str] = frozenset(
    {
        "$add",
        "$set",
        "$setonce",
        "$append",
        "$prepend",
        "$remove",
        "$unset",
        "$union",
        "$delete",
        "$inc",
        "$push",
        "$pull",
        "$pop",
        "$rename",
        "$min",
        "$max",
        "$mul",
        "$bit",
    }
)

_SECRET_ENV_KEYWORDS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "credential",
    "auth",
    "private",
    "passwd",
    "api_key",
    "apikey",
)


def run_url_domain_filter(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Iterate fields, extract URLs, apply url_filter + domain_check predicates."""
    url_filter_name = match_config.get("url_filter", "any_url")
    domain_check_name = match_config["domain_check"]
    score_map: dict[str, int] = match_config.get("score_map", {})

    url_filter_fn = _URL_FILTERS[url_filter_name]
    domain_check_fn = _DOMAIN_CHECKS[domain_check_name]

    desc_tpl = metadata.get("description_template", metadata.get("description", ""))
    findings: list[FindingCandidate] = []

    for field in ctx.parsed.fields:
        for raw_url in URL_PATTERN.findall(field.value):
            url = normalize_url(raw_url)
            domain = extract_domain(url)
            if not domain:
                continue

            result = url_filter_fn(url, domain, ctx)
            if result is False:
                continue

            check_result = domain_check_fn(domain, ctx)
            if check_result is False:
                continue

            score = base_score
            description = desc_tpl
            confidence = metadata["confidence"]

            if isinstance(check_result, dict):
                score = check_result.get("score", base_score)
                description = check_result.get("description", desc_tpl)
                confidence = check_result.get("confidence", confidence)

            if score_map:
                for condition_name, mapped_score in score_map.items():
                    if condition_name in str(check_result):
                        score = mapped_score

            description = _format_template(description, url=url, domain=domain)

            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=score,
                    confidence=confidence,
                    title=metadata["title"],
                    description=description,
                    evidence=field_evidence(ctx.parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_ip_address_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan fields for raw IPv4/IPv6 addresses."""
    score_public: int = match_config.get("score_public", base_score)
    score_non_public: int = match_config.get("score_non_public", base_score)

    findings: list[FindingCandidate] = []
    for field in ctx.parsed.fields:
        ips = _extract_raw_ip_addresses(field.value)
        for ip_addr in ips:
            non_public = _is_non_public_ip(ip_addr)
            score = score_non_public if non_public else score_public
            if non_public:
                desc = f"Configuration references a non-public raw IP address ({ip_addr.compressed})."
            else:
                desc = (
                    f"Configuration references a public raw IP address ({ip_addr.compressed}), "
                    "bypassing domain controls."
                )
            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=score,
                    confidence="high",
                    title=metadata["title"],
                    description=desc,
                    evidence=field_evidence(ctx.parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )
            break

    return dedupe_candidates(findings) if do_dedupe else findings


def run_key_pattern_match(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan document keys for keyword matches."""
    keywords: list[str] = match_config.get("keywords", [])
    match_mode: str = match_config.get("match_mode", "contains")
    skip_placeholder_values: bool = match_config.get("skip_placeholder_values", False)
    skip_placeholder_values_anywhere: bool = match_config.get("skip_placeholder_values_anywhere", False)
    desc_tpl = metadata.get("description_template", metadata.get("description", ""))
    keyword_set = frozenset(keywords)
    fields_by_line = {field.line: field for field in ctx.parsed.fields}

    findings: list[FindingCandidate] = []
    for key in ctx.parsed.keys:
        normalized_key = key.key.lower()
        matched = False
        if match_mode == "exact":
            matched = normalized_key in keyword_set
        else:
            matched = any(kw in normalized_key for kw in keywords)

        if matched:
            field = fields_by_line.get(key.line)
            if (
                skip_placeholder_values
                and field is not None
                and _is_placeholder_secret_value(field.value)
                and (field.in_code_block or skip_placeholder_values_anywhere)
            ):
                continue
            description = _format_template(desc_tpl, key=key.key)
            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=description,
                    evidence=Evidence(
                        path=str(ctx.parsed.file_path),
                        line=key.line,
                        snippet=key.snippet,
                    ),
                    recommendation=metadata["recommendation"],
                )
            )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_field_pattern_match(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan field values with a regex pattern."""
    pattern_str: str = match_config["pattern"]
    exclude_fn_name: str | None = match_config.get("exclude_pattern_fn")
    compiled = re.compile(pattern_str, re.IGNORECASE)
    exclude_fn = _EXCLUDE_FUNCTIONS.get(exclude_fn_name) if exclude_fn_name else None

    findings: list[FindingCandidate] = []
    for field in ctx.parsed.fields:
        if not compiled.search(field.value):
            continue
        if exclude_fn and exclude_fn(field.value):
            continue
        findings.append(
            FindingCandidate(
                rule_id="",
                score=base_score,
                confidence=metadata["confidence"],
                title=metadata["title"],
                description=metadata.get("description", ""),
                evidence=field_evidence(ctx.parsed, field),
                recommendation=metadata["recommendation"],
            )
        )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_entropy_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Check field values for length, entropy, and base64 patterns."""
    min_length: int = match_config.get("min_length", 80)
    min_entropy: float = match_config.get("min_entropy", 4.5)
    base64_pattern_str: str | None = match_config.get("base64_pattern")
    skip_prose: bool = match_config.get("skip_prose", False)
    prose_min_words: int = match_config.get("prose_min_words", _PROSE_MIN_WORDS_DEFAULT)

    base64_re = re.compile(base64_pattern_str) if base64_pattern_str else None
    findings: list[FindingCandidate] = []

    for field in ctx.parsed.fields:
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
                    rule_id="",
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=metadata.get("description", ""),
                    evidence=field_evidence(ctx.parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_hint_count(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Count strong/weak hints in raw text with optional negation awareness."""
    strong_hints: list[str] = match_config.get("strong_hints", [])
    weak_hints: list[str] = match_config.get("weak_hints", [])
    min_hint_count: int = match_config.get("min_hint_count", 2)
    require_strong: bool = match_config.get("require_strong", False)
    negation_aware: bool = match_config.get("negation_aware", False)

    lowered = ctx.parsed.raw_text.lower()

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
    evidence = _best_evidence_for_hint(ctx.parsed, best_hint)

    return [
        FindingCandidate(
            rule_id="",
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", ""),
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
    ]


def run_keyword_in_text(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Search raw text for keyword phrases."""
    hints: list[str] = match_config.get("hints", [])
    first_match_only: bool = match_config.get("first_match_only", True)

    lowered = ctx.parsed.raw_text.lower()
    for hint in hints:
        if hint not in lowered:
            continue

        evidence = _first_field_with_keyword(ctx.parsed, hint.split()[0])
        finding = FindingCandidate(
            rule_id="",
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", ""),
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
        if first_match_only:
            return [finding]

    return []


def run_token_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Find uppercase tool tokens via prefixes and optional service patterns."""
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
    desc_tpl = metadata.get("description_template", metadata.get("description", ""))
    seen_tokens: set[str] = set()
    findings: list[FindingCandidate] = []
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
            description = _format_template(desc_tpl, token=token)
            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=description,
                    evidence=field_evidence(ctx.parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )

    return dedupe_candidates(findings) if do_dedupe else findings


def run_frontmatter_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Inspect frontmatter structure for specific keys/values."""
    fm_path: str = match_config.get("path", "")
    empty_check: bool = match_config.get("empty_check", True)

    if not isinstance(ctx.parsed.frontmatter, dict):
        return []

    value = _resolve_frontmatter_path(ctx.parsed.frontmatter, fm_path)
    if value is None:
        return []

    if empty_check and _is_empty_value(value):
        return []

    evidence = _first_field_with_keyword(ctx.parsed, fm_path.split(".")[-1])
    return [
        FindingCandidate(
            rule_id="",
            score=base_score,
            confidence=metadata["confidence"],
            title=metadata["title"],
            description=metadata.get("description", ""),
            evidence=evidence,
            recommendation=metadata["recommendation"],
        )
    ]


def run_typosquat_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Compare skill name against baseline using edit distance."""
    max_distance: int = match_config.get("max_distance", 2)
    min_name_length: int = match_config.get("min_name_length", 5)
    baseline_source: str = match_config.get("baseline_source", "config.typosquat_baseline")
    desc_tpl = metadata.get("description_template", metadata.get("description", ""))

    if baseline_source == "config.typosquat_baseline":
        baseline = ctx.config.typosquat_baseline
    else:
        baseline = tuple(match_config.get("baseline", []))

    if not baseline:
        return []

    names_to_check = [ctx.skill_name]
    declared_name = _declared_name(ctx.parsed)
    if declared_name:
        names_to_check.append(declared_name)

    for candidate_name in names_to_check:
        normalized = normalize_similarity_name(candidate_name)
        for base in baseline:
            base_norm = normalize_similarity_name(base)
            if normalized == base_norm:
                continue
            dist = _levenshtein_distance(normalized, base_norm)
            too_close = dist <= max_distance
            long_enough = min(len(normalized), len(base_norm)) >= min_name_length
            if too_close and long_enough:
                description = _format_template(desc_tpl, name=candidate_name, value=base)
                return [
                    FindingCandidate(
                        rule_id="",
                        score=base_score,
                        confidence=metadata["confidence"],
                        title=metadata["title"],
                        description=description,
                        evidence=Evidence(
                            path=str(ctx.parsed.file_path),
                            line=1,
                            snippet=(ctx.parsed.raw_text.splitlines()[0][:200] if ctx.parsed.raw_text else ""),
                        ),
                        recommendation=metadata["recommendation"],
                    )
                ]

    return []


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


OP_REGISTRY: dict[str, Any] = {
    "url_domain_filter": run_url_domain_filter,
    "ip_address_scan": run_ip_address_scan,
    "key_pattern_match": run_key_pattern_match,
    "field_pattern_match": run_field_pattern_match,
    "entropy_check": run_entropy_check,
    "hint_count": run_hint_count,
    "keyword_in_text": run_keyword_in_text,
    "token_scan": run_token_scan,
    "frontmatter_check": run_frontmatter_check,
    "typosquat_check": run_typosquat_check,
    "bundled_scripts_check": run_bundled_scripts_check,
}


def _any_url(url: str, domain: str, ctx: EvalContext) -> bool:
    return True


def _is_mcp_endpoint(url: str, domain: str, ctx: EvalContext) -> bool:
    cleaned = normalize_url(url)
    parsed = urlparse(cleaned)
    path = parsed.path.lower()
    return path == MCP_PATH_TOKEN or path.endswith(MCP_PATH_TOKEN) or f"{MCP_PATH_TOKEN}/" in path


def _skip_ip_addresses(url: str, domain: str, ctx: EvalContext) -> bool:
    """Return False for IP-based URLs (handled by ip_address_scan)."""
    return _parse_ip_address(domain) is None


_URL_FILTERS: dict[str, Any] = {
    "any_url": _any_url,
    "is_mcp_endpoint": _is_mcp_endpoint,
    "skip_ip_addresses": _skip_ip_addresses,
}


def _not_allowlisted(domain: str, ctx: EvalContext) -> bool | dict[str, Any]:
    """For NET_UNKNOWN_DOMAIN: complex multi-path domain check."""
    if ctx.config.suppress_local_hosts and _is_local_dev_host(domain):
        return False

    if is_denylisted(domain, ctx.config.denylist_domains):
        return {
            "score": 80,
            "confidence": "high",
            "description": f"Configuration references '{domain}', which is denylisted.",
        }

    if is_allowlisted(domain, ctx.config.effective_allowlist_domains):
        return False

    score = 55 if ctx.config.allowlist_domains else 35
    confidence = "medium" if ctx.config.allowlist_domains else "low"
    return {
        "score": score,
        "confidence": confidence,
        "description": f"Configuration references external domain '{domain}'.",
    }


def _is_denylisted_domain(domain: str, ctx: EvalContext) -> bool:
    return is_denylisted(domain, ctx.config.mcp_denylist_domains)


def _not_mcp_allowlisted(domain: str, ctx: EvalContext) -> bool:
    return not is_allowlisted(domain, ctx.config.mcp_allowlist_domains)


def _is_allowlisted_only(domain: str, ctx: EvalContext) -> bool:
    """For EXTERNAL_URLS: only fire for allowlisted domains."""
    return is_allowlisted(domain, ctx.config.allowlist_domains)


_DOMAIN_CHECKS: dict[str, Any] = {
    "not_allowlisted": _not_allowlisted,
    "is_denylisted": _is_denylisted_domain,
    "not_mcp_allowlisted": _not_mcp_allowlisted,
    "is_allowlisted_only": _is_allowlisted_only,
}


def _is_non_secret_env_ref(value: str) -> bool:
    """Return True when env-var references are non-secret operators."""
    for match in ENV_REF_PATTERN.finditer(value):
        ref = match.group(0).lower().strip("${} ")
        if ref in _NON_SECRET_ENV_OPERATORS:
            continue
        if any(kw in ref for kw in _SECRET_ENV_KEYWORDS):
            return False
    return True


def _is_placeholder_secret_value(value: str) -> bool:
    return bool(SECRET_PLACEHOLDER_VALUE_PATTERN.search(value))


def _service_prefixes(match_config: dict[str, Any]) -> tuple[str, ...]:
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


_EXCLUDE_FUNCTIONS: dict[str, Any] = {
    "is_non_secret_env_ref": _is_non_secret_env_ref,
}


def _parse_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        parsed = ipaddress.ip_address(value.strip().strip("[]"))
        if isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return parsed
        return None
    except ValueError:
        return None


def _is_local_dev_host(domain: str) -> bool:
    if domain in LOCAL_DEV_HOSTS:
        return True
    if domain in RESERVED_EXAMPLE_DOMAINS:
        return True
    return any(domain.endswith(tld) for tld in LOCAL_DEV_TLDS)


def _extract_raw_ip_addresses(value: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    extracted: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for url in URL_PATTERN.findall(value):
        domain = extract_domain(url)
        if not domain:
            continue
        parsed = _parse_ip_address(domain)
        if parsed is not None:
            extracted.append(parsed)
    for ipv4 in IP_PATTERN.findall(value):
        parsed = _parse_ip_address(ipv4)
        if parsed is not None:
            extracted.append(parsed)
    for ipv6 in BRACKET_IPV6_PATTERN.findall(value):
        parsed = _parse_ip_address(ipv6)
        if parsed is not None:
            extracted.append(parsed)
    return extracted


def _is_non_public_ip(ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip_addr.is_private
        or ip_addr.is_loopback
        or ip_addr.is_link_local
        or ip_addr.is_multicast
        or ip_addr.is_reserved
        or ip_addr.is_unspecified
    )


def _shannon_entropy(value: str) -> float:
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


def _looks_like_prose(value: str, min_words: int = 3) -> bool:
    if " " not in value:
        return False
    return len(value.split()) >= min_words


def _levenshtein_distance(left: str, right: str) -> int:
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


def _hint_is_negated(lowered_text: str, hint: str) -> bool:
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


def _first_field_with_keyword(parsed: ParsedSkillDocument, keyword: str) -> Evidence:
    kw_lower = keyword.lower()
    for field in parsed.fields:
        if kw_lower in field.value.lower():
            return field_evidence(parsed, field)
    raw_lines = parsed.raw_text.splitlines()
    first_line = raw_lines[0] if raw_lines else ""
    return Evidence(path=str(parsed.file_path), line=1, snippet=first_line[:200])


def _resolve_frontmatter_path(fm: dict[str, Any], dotted_path: str) -> Any:
    parts = dotted_path.split(".")
    current: Any = fm
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _is_empty_value(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def _declared_name(parsed: ParsedSkillDocument) -> str | None:
    if isinstance(parsed.frontmatter, dict):
        name = parsed.frontmatter.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return None


def _format_template(template: str, **kwargs: str) -> str:
    """Safe template formatting — missing keys left as literal {key}."""
    result = template
    for key, value in kwargs.items():
        result = result.replace(f"{{{key}}}", value)
    return result
