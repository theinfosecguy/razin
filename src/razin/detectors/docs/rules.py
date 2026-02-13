"""Doc-based detectors for MCP/tool exposure in SKILL.md files."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from razin.config import RaisinConfig
from razin.constants.detectors import URL_PATTERN
from razin.constants.docs import (
    AUTH_CONNECTION_SCORE,
    AUTH_MIN_HINT_COUNT,
    AUTH_STRONG_HINTS,
    AUTH_WEAK_HINTS,
    DYNAMIC_SCHEMA_HINTS,
    DYNAMIC_SCHEMA_SCORE,
    EXTERNAL_URLS_SCORE,
    MCP_DENYLIST_SCORE,
    MCP_ENDPOINT_SCORE,
    MCP_PATH_TOKEN,
    MCP_REQUIRED_SCORE,
    TOOL_INVOCATION_SCORE,
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
        config: RaisinConfig,
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
        config: RaisinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for field, url, domain in _iter_urls(parsed):
            if not _looks_like_mcp_endpoint(url):
                continue
            if is_allowlisted(domain, config.mcp_allowlist_domains):
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
        config: RaisinConfig,
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
    """Detect uppercase tool invocation tokens in docs."""

    rule_id = "TOOL_INVOCATION"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RaisinConfig,
    ) -> list[FindingCandidate]:
        prefixes = tuple(prefix for prefix in config.tool_prefixes if prefix)
        if not prefixes:
            return []

        findings: list[FindingCandidate] = []
        for field in parsed.fields:
            for token in TOOL_TOKEN_PATTERN.findall(field.value):
                if not token.startswith(prefixes):
                    continue

                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=TOOL_INVOCATION_SCORE,
                        confidence="medium",
                        title="Tool invocation token in docs",
                        description=f"Documentation references tool token '{token}'.",
                        evidence=field_evidence(parsed, field),
                        recommendation=("Verify tool token permissions and enforce explicit " "invocation policies."),
                    )
                )

        return dedupe_candidates(findings)


class DynamicSchemaDetector(Detector):
    """Detect instructions that imply dynamic schema/tool discovery."""

    rule_id = "DYNAMIC_SCHEMA"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RaisinConfig,
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
        config: RaisinConfig,
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
        config: RaisinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        for field, url, domain in _iter_urls(parsed):
            # Skip non-allowlisted domains — those are covered by the
            # policy-level NET_UNKNOWN_DOMAIN detector.
            if not is_allowlisted(domain, config.allowlist_domains):
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
        for prefix in _NEGATION_PREFIXES:
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


# Negation prefixes checked line-by-line for AUTH_CONNECTION hints.
_NEGATION_PREFIXES: tuple[str, ...] = (
    "no ",
    "not ",
    "without ",
    "don't need",
    "doesn't require",
    "no need for",
    "not require",
    "not needed",
)


def _hint_is_negated(lowered_text: str, hint: str) -> bool:
    """Return True when *every* occurrence of `hint` in the text is negated."""
    if hint not in lowered_text:
        return True  # not present at all

    for line in lowered_text.splitlines():
        if hint not in line:
            continue
        negated = False
        for prefix in _NEGATION_PREFIXES:
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
