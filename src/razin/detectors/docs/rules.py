"""Doc-based detectors for MCP/tool exposure in SKILL.md files."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from razin.config import RazinConfig
from razin.constants.detectors import URL_PATTERN
from razin.constants.docs import (
    AUTH_CONNECTION_SCORE,
    AUTH_MIN_HINT_COUNT,
    AUTH_STRONG_HINTS,
    AUTH_WEAK_HINTS,
    DEFAULT_SERVICE_TOOL_PREFIXES,
    DYNAMIC_SCHEMA_HINTS,
    DYNAMIC_SCHEMA_SCORE,
    EXTERNAL_URLS_SCORE,
    MCP_DENYLIST_SCORE,
    MCP_ENDPOINT_SCORE,
    MCP_PATH_TOKEN,
    MCP_REQUIRED_SCORE,
    NEGATION_PREFIXES,
    SERVICE_TOOL_MIN_TOTAL_LENGTH,
    SERVICE_TOOL_TOKEN_PATTERN,
    TOOL_CONSOLIDATION_MAX_SCORE,
    TOOL_CONSOLIDATION_TOP_N,
    TOOL_INVOCATION_SCORE,
    TOOL_TIER_DESTRUCTIVE_BONUS,
    TOOL_TIER_WRITE_BONUS,
    TOOL_TOKEN_PATTERN,
)
from razin.detectors.base import Detector
from razin.detectors.common import (
    dedupe_candidates,
    extract_domain,
    field_evidence,
    is_allowlisted,
    is_denylisted,
    normalize_url,
)
from razin.model import DocumentField, Evidence, FindingCandidate, ParsedSkillDocument

logger = logging.getLogger(__name__)


class McpRequiredDetector(Detector):
    """Detect frontmatter-declared MCP requirements."""

    rule_id = "MCP_REQUIRED"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        if not isinstance(parsed.frontmatter, dict):
            return []

        requires = parsed.frontmatter.get("requires")
        if not isinstance(requires, dict):
            return []

        mcp_value = requires.get("mcp")
        if _is_empty_requirement(mcp_value):
            return []

        evidence = _first_field_with_keyword(parsed, "mcp")
        return [
            FindingCandidate(
                rule_id=self.rule_id,
                score=MCP_REQUIRED_SCORE,
                confidence="high",
                title="MCP requirement declared",
                description="Frontmatter requires MCP connectivity for this skill.",
                evidence=evidence,
                recommendation=("Restrict MCP server access to approved endpoints and least-privilege tooling."),
            )
        ]


class McpEndpointDetector(Detector):
    """Detect MCP endpoint URLs in docs that are not allowlisted."""

    rule_id = "MCP_ENDPOINT"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for field, url, domain in _iter_urls(parsed):
            if not _looks_like_mcp_endpoint(url):
                continue
            if is_allowlisted(domain, config.mcp_allowlist_domains, strict=config.strict_subdomains):
                continue

            findings.append(
                FindingCandidate(
                    rule_id=self.rule_id,
                    score=MCP_ENDPOINT_SCORE,
                    confidence="high",
                    title="MCP endpoint in docs",
                    description=f"Documentation references MCP endpoint '{url}'.",
                    evidence=field_evidence(parsed, field),
                    recommendation=("Constrain MCP endpoints with allowlists and verify endpoint ownership."),
                )
            )

        return dedupe_candidates(findings)


class McpDenylistDetector(Detector):
    """Detect MCP endpoints matching explicit denylist policy."""

    rule_id = "MCP_DENYLIST"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        if not config.mcp_denylist_domains:
            return []

        findings: list[FindingCandidate] = []
        for field, url, domain in _iter_urls(parsed):
            if not _looks_like_mcp_endpoint(url):
                continue
            if not is_denylisted(domain, config.mcp_denylist_domains):
                continue

            findings.append(
                FindingCandidate(
                    rule_id=self.rule_id,
                    score=MCP_DENYLIST_SCORE,
                    confidence="high",
                    title="Denylisted MCP endpoint",
                    description=f"MCP endpoint '{url}' matches denylist policy.",
                    evidence=field_evidence(parsed, field),
                    recommendation="Remove denylisted MCP endpoint references from docs.",
                )
            )

        return dedupe_candidates(findings)


class ToolInvocationDetector(Detector):
    """Detect uppercase tool invocation tokens and consolidate into one finding."""

    rule_id = "TOOL_INVOCATION"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        prefixes = tuple(prefix.upper() for prefix in config.tool_prefixes if prefix)
        if not prefixes:
            return []

        service_prefixes = tuple(prefix.upper() for prefix in DEFAULT_SERVICE_TOOL_PREFIXES)
        seen_tokens: set[str] = set()
        first_evidence: Evidence | None = None
        for field in parsed.fields:
            for token in TOOL_TOKEN_PATTERN.findall(field.value):
                if token in seen_tokens:
                    continue
                if not token.startswith(prefixes) and not _matches_service_tool_token(
                    token,
                    service_prefixes=service_prefixes,
                    token_re=SERVICE_TOOL_TOKEN_PATTERN,
                ):
                    continue
                seen_tokens.add(token)
                if first_evidence is None:
                    first_evidence = field_evidence(parsed, field)

        if not seen_tokens:
            return []

        destructive_kw = config.tool_tier_keywords.destructive
        write_kw = config.tool_tier_keywords.write

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

        score = TOOL_INVOCATION_SCORE + min(len(seen_tokens), 10) * 2
        score += len(destructive_tokens) * TOOL_TIER_DESTRUCTIVE_BONUS
        score += len(write_tokens) * TOOL_TIER_WRITE_BONUS
        score = min(score, TOOL_CONSOLIDATION_MAX_SCORE)

        total = len(seen_tokens)
        desc_parts: list[str] = [
            f"Skill references {total} tool invocation token{'s' if total != 1 else ''}.",
        ]
        tier_parts: list[str] = []
        if destructive_tokens:
            tier_parts.append(f"{len(destructive_tokens)} destructive")
        if write_tokens:
            tier_parts.append(f"{len(write_tokens)} write")
        if read_tokens:
            tier_parts.append(f"{len(read_tokens)} read")
        if tier_parts:
            desc_parts.append(f"Tiers: {', '.join(tier_parts)}.")

        sorted_tokens = sorted(seen_tokens)
        snippet_tokens = sorted_tokens[:TOOL_CONSOLIDATION_TOP_N]
        snippet = ", ".join(snippet_tokens)
        if len(sorted_tokens) > TOOL_CONSOLIDATION_TOP_N:
            snippet += f" (+{len(sorted_tokens) - TOOL_CONSOLIDATION_TOP_N} more)"

        assert first_evidence is not None
        evidence = Evidence(
            path=first_evidence.path,
            line=first_evidence.line,
            snippet=snippet,
        )

        return [
            FindingCandidate(
                rule_id=self.rule_id,
                score=score,
                confidence="medium",
                title="Tool invocation tokens in docs",
                description=" ".join(desc_parts),
                evidence=evidence,
                recommendation=(
                    "Verify tool token permissions and enforce explicit "
                    "invocation policies. Review destructive and write-tier tokens closely."
                ),
            )
        ]


class DynamicSchemaDetector(Detector):
    """Detect instructions that imply dynamic schema/tool discovery."""

    rule_id = "DYNAMIC_SCHEMA"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        lowered = parsed.raw_text.lower()
        for hint in DYNAMIC_SCHEMA_HINTS:
            if hint not in lowered:
                continue

            evidence = _first_field_with_keyword(parsed, hint.split()[0])
            return [
                FindingCandidate(
                    rule_id=self.rule_id,
                    score=DYNAMIC_SCHEMA_SCORE,
                    confidence="low",
                    title="Dynamic schema discovery guidance",
                    description=("Docs suggest discovering tools/schema at runtime before " "execution."),
                    evidence=evidence,
                    recommendation=("Review runtime-discovery flows and pin trusted schemas where possible."),
                )
            ]

        return []


class AuthConnectionDetector(Detector):
    """Detect auth and connection setup guidance in docs."""

    rule_id = "AUTH_CONNECTION"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        lowered = parsed.raw_text.lower()

        # Collect non-negated strong and weak matches separately.
        strong_matches = [hint for hint in AUTH_STRONG_HINTS if hint in lowered and not _hint_is_negated(lowered, hint)]
        weak_matches = [hint for hint in AUTH_WEAK_HINTS if hint in lowered and not _hint_is_negated(lowered, hint)]

        # Require at least 1 strong hint.  Weak hints alone (e.g. "token"
        # from pagination, "connect" from MCP language) are not enough.
        if not strong_matches:
            return []

        all_matches = strong_matches + weak_matches
        if len(all_matches) < AUTH_MIN_HINT_COUNT:
            return []

        # Pick the best evidence line: prefer the strongest auth hint.
        best_hint = strong_matches[0]
        evidence = _best_evidence_for_hint(parsed, best_hint)

        return [
            FindingCandidate(
                rule_id=self.rule_id,
                score=AUTH_CONNECTION_SCORE,
                confidence="medium",
                title="Auth/connection requirements in docs",
                description="Docs include authentication or connection setup requirements.",
                evidence=evidence,
                recommendation=(
                    "Validate auth flows, secret handling, and connection " "policies before enabling skill."
                ),
            )
        ]


class ExternalUrlsDetector(Detector):
    """Detect external URLs present anywhere in skill documentation.

    This is a context-level signal.  When the same URL domain is also
    flagged by the policy-level NET_UNKNOWN_DOMAIN detector (i.e. the
    domain is not on the allowlist), this detector skips it to avoid
    duplicate evidence.  It fires only for allowlisted-domain URLs that
    NET_UNKNOWN_DOMAIN would not cover.
    """

    rule_id = "EXTERNAL_URLS"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        for field, url, domain in _iter_urls(parsed):
            # Skip non-allowlisted domains — those are covered by the
            # policy-level NET_UNKNOWN_DOMAIN detector.
            if not is_allowlisted(domain, config.allowlist_domains, strict=config.strict_subdomains):
                continue
            findings.append(
                FindingCandidate(
                    rule_id=self.rule_id,
                    score=EXTERNAL_URLS_SCORE,
                    confidence="low",
                    title="External URL in docs",
                    description=f"Documentation references external URL '{url}'.",
                    evidence=field_evidence(parsed, field),
                    recommendation=("Review external URLs and constrain network access where " "possible."),
                )
            )

        return dedupe_candidates(findings)


DOC_DETECTOR_CLASSES: tuple[type[Detector], ...] = (
    McpRequiredDetector,
    McpEndpointDetector,
    McpDenylistDetector,
    ToolInvocationDetector,
    DynamicSchemaDetector,
    AuthConnectionDetector,
    ExternalUrlsDetector,
)


def _iter_urls(
    parsed: ParsedSkillDocument,
) -> list[tuple[DocumentField, str, str]]:
    """Yield field, normalized URL, and normalized domain tuples from all parsed lines."""
    rows: list[tuple[DocumentField, str, str]] = []
    for field in parsed.fields:
        for raw_url in URL_PATTERN.findall(field.value):
            url = normalize_url(raw_url)
            domain = extract_domain(url)
            if not domain:
                continue
            rows.append((field, url, domain))
    return rows


def _looks_like_mcp_endpoint(url: str) -> bool:
    cleaned = normalize_url(url)
    parsed = urlparse(cleaned)
    path = parsed.path.lower()
    return path == MCP_PATH_TOKEN or path.endswith(MCP_PATH_TOKEN) or f"{MCP_PATH_TOKEN}/" in path


def _first_field_with_keyword(parsed: ParsedSkillDocument, keyword: str) -> Evidence:
    keyword_lower = keyword.lower()
    for field in parsed.fields:
        if keyword_lower in field.value.lower():
            return field_evidence(parsed, field)
    raw_lines = parsed.raw_text.splitlines()
    first_line = raw_lines[0] if raw_lines else ""
    return Evidence(path=str(parsed.file_path), line=1, snippet=first_line[:200])


def _best_evidence_for_hint(parsed: ParsedSkillDocument, hint: str) -> Evidence:
    """Return evidence from the field that best matches *hint*.

    Prefers lines where the hint appears in a non-negated context.
    Falls back to ``_first_field_with_keyword`` if no ideal match found.
    """
    hint_lower = hint.lower()
    best_field = None
    for field in parsed.fields:
        line_lower = field.value.lower()
        if hint_lower not in line_lower:
            continue
        # Skip negated lines.
        negated = False
        for prefix in NEGATION_PREFIXES:
            idx = line_lower.find(hint_lower)
            window_start = max(0, idx - 30)
            window = line_lower[window_start:idx]
            if prefix in window:
                negated = True
                break
        if not negated:
            best_field = field
            break  # first non-negated occurrence wins
    if best_field is not None:
        return field_evidence(parsed, best_field)
    return _first_field_with_keyword(parsed, hint.split()[0])


def _is_empty_requirement(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def _hint_is_negated(lowered_text: str, hint: str) -> bool:
    """Return True when *every* occurrence of `hint` in the text is negated."""
    if hint not in lowered_text:
        return True  # not present at all

    for line in lowered_text.splitlines():
        if hint not in line:
            continue
        negated = False
        for prefix in NEGATION_PREFIXES:
            idx = line.find(hint)
            # Check up to 30 chars before the hint for a negation prefix.
            window_start = max(0, idx - 30)
            window = line[window_start:idx]
            if prefix in window:
                negated = True
                break
        if not negated:
            return False  # found at least one non-negated occurrence
    return True


def _matches_service_tool_token(
    token: str,
    *,
    service_prefixes: tuple[str, ...],
    token_re: re.Pattern[str],
) -> bool:
    if len(token) < SERVICE_TOOL_MIN_TOTAL_LENGTH:
        return False
    if not token_re.fullmatch(token):
        return False
    segments = token.split("_")
    if len(segments) < 3:
        return False
    return segments[0] in service_prefixes


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
