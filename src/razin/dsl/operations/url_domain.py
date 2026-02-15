"""URL/domain filter operations for DSL rules."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from razin.constants.detectors import URL_PATTERN
from razin.constants.docs import MCP_PATH_TOKEN
from razin.detectors.common import (
    dedupe_candidates,
    extract_domain,
    field_evidence,
    is_allowlisted,
    is_denylisted,
    normalize_url,
)
from razin.dsl.operations.shared import (
    format_template,
    is_local_dev_host,
    parse_ip_address,
)
from razin.model import FindingCandidate
from razin.types.dsl import EvalContext


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
    field_source_filter: list[str] | None = match_config.get("field_source_filter")

    url_filter_fn = _URL_FILTERS[url_filter_name]
    domain_check_fn = _DOMAIN_CHECKS[domain_check_name]

    desc_tpl = metadata.get("description_template", metadata.get("description", ""))
    findings: list[FindingCandidate] = []

    for field in ctx.parsed.fields:
        if field_source_filter and field.field_source not in field_source_filter:
            continue
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

            description = format_template(description, url=url, domain=domain)

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


def _any_url(url: str, domain: str, ctx: EvalContext) -> bool:
    """Accept any URL."""
    return True


def _is_mcp_endpoint(url: str, domain: str, ctx: EvalContext) -> bool:
    """Return True when the URL path looks like an MCP endpoint."""
    cleaned = normalize_url(url)
    parsed = urlparse(cleaned)
    path = parsed.path.lower()
    return path == MCP_PATH_TOKEN or path.endswith(MCP_PATH_TOKEN) or f"{MCP_PATH_TOKEN}/" in path


def _skip_ip_addresses(url: str, domain: str, ctx: EvalContext) -> bool:
    """Return False for IP-based URLs (handled by ip_address_scan)."""
    return parse_ip_address(domain) is None


_URL_FILTERS: dict[str, Any] = {
    "any_url": _any_url,
    "is_mcp_endpoint": _is_mcp_endpoint,
    "skip_ip_addresses": _skip_ip_addresses,
}


def _not_allowlisted(domain: str, ctx: EvalContext) -> bool | dict[str, Any]:
    """For NET_UNKNOWN_DOMAIN: complex multi-path domain check."""
    if ctx.config.suppress_local_hosts and is_local_dev_host(domain):
        return False

    if is_denylisted(domain, ctx.config.denylist_domains):
        return {
            "score": 80,
            "confidence": "high",
            "description": f"Configuration references '{domain}', which is denylisted.",
        }

    if is_allowlisted(domain, ctx.config.effective_allowlist_domains, strict=ctx.config.strict_subdomains):
        return False

    score = 55 if ctx.config.allowlist_domains else 35
    confidence = "medium" if ctx.config.allowlist_domains else "low"
    return {
        "score": score,
        "confidence": confidence,
        "description": f"Configuration references external domain '{domain}'.",
    }


def _is_denylisted_domain(domain: str, ctx: EvalContext) -> bool:
    """Return True when *domain* is in the MCP denylist."""
    return is_denylisted(domain, ctx.config.mcp_denylist_domains)


def _not_mcp_allowlisted(domain: str, ctx: EvalContext) -> bool:
    """Return True when *domain* is not in the MCP allowlist."""
    return not is_allowlisted(domain, ctx.config.mcp_allowlist_domains, strict=ctx.config.strict_subdomains)


def _is_allowlisted_only(domain: str, ctx: EvalContext) -> bool:
    """For EXTERNAL_URLS: only fire for allowlisted domains."""
    return is_allowlisted(domain, ctx.config.allowlist_domains, strict=ctx.config.strict_subdomains)


def _not_allowlisted_prose(domain: str, ctx: EvalContext) -> bool | dict[str, Any]:
    """For NET_DOC_DOMAIN: non-allowlisted or denylisted domains in prose fields."""
    if ctx.config.suppress_local_hosts and is_local_dev_host(domain):
        return False

    if is_denylisted(domain, ctx.config.denylist_domains):
        return {
            "score": 80,
            "confidence": "high",
            "description": f"Documentation references '{domain}', which is denylisted.",
        }

    if is_allowlisted(domain, ctx.config.effective_allowlist_domains, strict=ctx.config.strict_subdomains):
        return False

    return {
        "score": 15,
        "confidence": "low",
        "description": f"Documentation references external domain '{domain}'.",
    }


_DOMAIN_CHECKS: dict[str, Any] = {
    "not_allowlisted": _not_allowlisted,
    "not_allowlisted_prose": _not_allowlisted_prose,
    "is_denylisted": _is_denylisted_domain,
    "not_mcp_allowlisted": _not_mcp_allowlisted,
    "is_allowlisted_only": _is_allowlisted_only,
}
