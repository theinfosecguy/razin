"""Detector implementations for MVP rule set."""

from __future__ import annotations

import ipaddress
import logging
import math

from razin.config import RazinConfig
from razin.constants.detectors import (
    BASE64_PATTERN,
    BRACKET_IPV6_PATTERN,
    BUNDLED_SCRIPTS_SCORE,
    ENV_REF_PATTERN,
    EXEC_FIELD_NAMES,
    EXEC_FIELDS_SCORE,
    IP_PATTERN,
    LOCAL_DEV_HOSTS,
    LOCAL_DEV_TLDS,
    NET_DENYLIST_DOMAIN_SCORE,
    NET_RAW_IP_NON_PUBLIC_SCORE,
    NET_RAW_IP_PUBLIC_SCORE,
    NET_UNKNOWN_DOMAIN_ALLOWLIST_SCORE,
    NET_UNKNOWN_DOMAIN_OPEN_SCORE,
    OPAQUE_BLOB_SCORE,
    OPAQUE_MIN_ENTROPY,
    OPAQUE_MIN_LENGTH,
    RESERVED_EXAMPLE_DOMAINS,
    SCRIPT_FILE_EXTENSIONS,
    SECRET_ENV_REF_SCORE,
    SECRET_KEY_SCORE,
    SECRET_KEYWORDS,
    SECRET_PLACEHOLDER_VALUE_PATTERN,
    TYPOSQUAT_MAX_DISTANCE,
    TYPOSQUAT_MIN_NAME_LENGTH,
    TYPOSQUAT_SCORE,
    URL_PATTERN,
)
from razin.constants.parsing import SNIPPET_MAX_LENGTH
from razin.detectors.base import Detector
from razin.detectors.common import (
    dedupe_candidates,
    extract_domain,
    field_evidence,
    is_allowlisted,
    is_denylisted,
    normalize_url,
)
from razin.detectors.docs import DOC_DETECTOR_CLASSES
from razin.model import Evidence, FindingCandidate, ParsedSkillDocument
from razin.utils import normalize_similarity_name

logger = logging.getLogger(__name__)


class NetRawIpDetector(Detector):
    """Detect network endpoints pointing directly to raw IPv4 addresses."""

    rule_id = "NET_RAW_IP"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for field in parsed.fields:
            for ip_address in _extract_raw_ip_addresses(field.value):
                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=_raw_ip_score(ip_address),
                        confidence="high",
                        title="Raw IP endpoint in config",
                        description=_raw_ip_description(ip_address),
                        evidence=field_evidence(parsed, field),
                        recommendation=("Replace raw IP endpoints with approved DNS domains " "and allowlist checks."),
                    )
                )
                break
        return dedupe_candidates(findings)


class NetUnknownDomainDetector(Detector):
    """Detect network domains not in allowlist or explicitly denylisted."""

    rule_id = "NET_UNKNOWN_DOMAIN"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for field in parsed.fields:
            for raw_url in URL_PATTERN.findall(field.value):
                url = normalize_url(raw_url)
                domain = extract_domain(url)
                if not domain or _parse_ip_address(domain) is not None:
                    continue

                # Suppress local/dev/example hosts when profile enables it.
                if config.suppress_local_hosts and _is_local_dev_host(domain):
                    continue

                if is_denylisted(domain, config.denylist_domains):
                    findings.append(
                        FindingCandidate(
                            rule_id=self.rule_id,
                            score=NET_DENYLIST_DOMAIN_SCORE,
                            confidence="high",
                            title="Denylisted domain in config",
                            description=(f"Configuration references '{domain}', which is " "denylisted."),
                            evidence=field_evidence(parsed, field),
                            recommendation="Remove or replace denylisted domains.",
                        )
                    )
                    continue

                if is_allowlisted(domain, config.effective_allowlist_domains):
                    continue

                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=(
                            NET_UNKNOWN_DOMAIN_ALLOWLIST_SCORE
                            if config.allowlist_domains
                            else NET_UNKNOWN_DOMAIN_OPEN_SCORE
                        ),
                        confidence="medium" if config.allowlist_domains else "low",
                        title="Non-allowlisted domain in config",
                        description=f"Configuration references external domain '{domain}'.",
                        evidence=field_evidence(parsed, field),
                        recommendation=("Restrict outbound domains with allowlists and verify ownership."),
                    )
                )
        return dedupe_candidates(findings)


class SecretRefDetector(Detector):
    """Detect secret-like keys and environment variable references."""

    rule_id = "SECRET_REF"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        fields_by_line = {field.line: field for field in parsed.fields}

        for key in parsed.keys:
            normalized_key = key.key.lower()
            if any(keyword in normalized_key for keyword in SECRET_KEYWORDS):
                field = fields_by_line.get(key.line)
                if field and _is_placeholder_secret_value(field.value):
                    continue
                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=SECRET_KEY_SCORE,
                        confidence="high",
                        title="Secret-like key in config",
                        description=(f"Key '{key.key}' appears to store or reference sensitive credentials."),
                        evidence=Evidence(
                            path=str(parsed.file_path),
                            line=key.line,
                            snippet=key.snippet,
                        ),
                        recommendation=("Store secrets in secret managers and avoid embedding them in config."),
                    )
                )

        for field in parsed.fields:
            if ENV_REF_PATTERN.search(field.value):
                # Filter out non-secret operator-like patterns ($add, $set, etc.)
                if _is_non_secret_env_ref(field.value):
                    continue
                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=SECRET_ENV_REF_SCORE,
                        confidence="medium",
                        title="Environment secret reference",
                        description="Configuration includes environment secret references.",
                        evidence=field_evidence(parsed, field),
                        recommendation=("Ensure referenced secrets are minimally scoped and never logged."),
                    )
                )

        return dedupe_candidates(findings)


class ExecFieldsDetector(Detector):
    """Detect executable command/script fields in config."""

    rule_id = "EXEC_FIELDS"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        for key in parsed.keys:
            if key.key.lower() in EXEC_FIELD_NAMES:
                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=EXEC_FIELDS_SCORE,
                        confidence="high",
                        title="Executable field in config",
                        description=f"Field '{key.key}' declares command-like behavior.",
                        evidence=Evidence(
                            path=str(parsed.file_path),
                            line=key.line,
                            snippet=key.snippet,
                        ),
                        recommendation="Review and constrain command execution fields.",
                    )
                )

        return dedupe_candidates(findings)


class OpaqueBlobDetector(Detector):
    """Detect suspiciously long or high-entropy values in config."""

    rule_id = "OPAQUE_BLOB"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        for field in parsed.fields:
            value = field.value.strip()
            if len(value) < OPAQUE_MIN_LENGTH:
                continue

            # Prose exclusion: if the value contains spaces and reads like
            # natural language, skip it — even if entropy is high due to
            # mixed-case tool names and markdown formatting.
            if _looks_like_prose(value):
                continue

            entropy = _shannon_entropy(value)
            looks_base64 = bool(BASE64_PATTERN.match(value))
            if looks_base64 or entropy >= OPAQUE_MIN_ENTROPY:
                findings.append(
                    FindingCandidate(
                        rule_id=self.rule_id,
                        score=OPAQUE_BLOB_SCORE,
                        confidence="medium",
                        title="Opaque or encoded blob detected",
                        description="Long or high-entropy value may hide encoded payloads.",
                        evidence=field_evidence(parsed, field),
                        recommendation=("Replace opaque inline blobs with reviewed external artifacts."),
                    )
                )

        return dedupe_candidates(findings)


class TyposquatDetector(Detector):
    """Detect names close to known baseline names."""

    rule_id = "TYPOSQUAT"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        if not config.typosquat_baseline:
            return []

        names_to_check = [skill_name]
        declared_name = _declared_name(parsed)
        if declared_name:
            names_to_check.append(declared_name)

        findings: list[FindingCandidate] = []
        for candidate_name in names_to_check:
            normalized_name = normalize_similarity_name(candidate_name)
            for baseline in config.typosquat_baseline:
                baseline_normalized = normalize_similarity_name(baseline)
                if normalized_name == baseline_normalized:
                    continue
                distance = _levenshtein_distance(normalized_name, baseline_normalized)
                too_close = distance <= TYPOSQUAT_MAX_DISTANCE
                sufficiently_long = min(len(normalized_name), len(baseline_normalized)) >= TYPOSQUAT_MIN_NAME_LENGTH
                if too_close and sufficiently_long:
                    findings.append(
                        FindingCandidate(
                            rule_id=self.rule_id,
                            score=TYPOSQUAT_SCORE,
                            confidence="medium",
                            title="Potential typosquat skill name",
                            description=(f"Skill name '{candidate_name}' is close to " f"baseline '{baseline}'."),
                            evidence=Evidence(
                                path=str(parsed.file_path),
                                line=1,
                                snippet=(parsed.raw_text.splitlines()[0][:200] if parsed.raw_text else ""),
                            ),
                            recommendation=("Verify package origin and exact spelling " "before trust or deployment."),
                        )
                    )
                    return findings
        return findings


class BundledScriptsDetector(Detector):
    """Detect bundled executable scripts alongside SKILL.md."""

    rule_id = "BUNDLED_SCRIPTS"

    def run(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        skill_dir = parsed.file_path.parent
        bundled: list[str] = []

        for path in skill_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.name == "SKILL.md":
                continue
            if path.suffix.lower() in SCRIPT_FILE_EXTENSIONS:
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
                rule_id=self.rule_id,
                score=BUNDLED_SCRIPTS_SCORE,
                confidence="medium",
                title="Bundled executable scripts detected",
                description=(
                    "Skill package includes executable script files alongside SKILL.md. "
                    "Review for hidden execution or data access risks."
                ),
                evidence=Evidence(
                    path=str(parsed.file_path),
                    line=None,
                    snippet=snippet,
                ),
                recommendation=("Audit bundled scripts before use; avoid running unreviewed code."),
            )
        ]


def build_detectors(rule_ids: tuple[str, ...]) -> list[Detector]:
    """Build detector instances for configured rule IDs."""
    known = {detector_cls.rule_id: detector_cls for detector_cls in DETECTOR_CLASSES}
    detectors: list[Detector] = []

    for rule_id in rule_ids:
        detector_cls = known.get(rule_id)
        if detector_cls is None:
            logger.warning("Unknown detector ID ignored", extra={"rule_id": rule_id})
            continue
        detectors.append(detector_cls())

    return detectors


DETECTOR_CLASSES: tuple[type[Detector], ...] = (
    NetRawIpDetector,
    NetUnknownDomainDetector,
    SecretRefDetector,
    ExecFieldsDetector,
    OpaqueBlobDetector,
    TyposquatDetector,
    BundledScriptsDetector,
    *DOC_DETECTOR_CLASSES,
)


def _parse_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse IPv4/IPv6 text and return an address object if valid."""
    try:
        parsed = ipaddress.ip_address(value.strip().strip("[]"))
        if isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return parsed
        return None
    except ValueError:
        return None


def _is_local_dev_host(domain: str) -> bool:
    """Return True if the domain is a local/dev/example host that should be suppressed."""
    if domain in LOCAL_DEV_HOSTS:
        return True
    if domain in RESERVED_EXAMPLE_DOMAINS:
        return True
    return any(domain.endswith(tld) for tld in LOCAL_DEV_TLDS)


def _extract_raw_ip_addresses(value: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Extract raw IPv4/IPv6 addresses from plain text and URL hosts."""
    extracted: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

    for url in URL_PATTERN.findall(value):
        domain = extract_domain(url)
        if not domain:
            continue
        parsed = _parse_ip_address(domain)
        if parsed is not None:
            extracted.append(parsed)

    for ipv4_candidate in IP_PATTERN.findall(value):
        parsed = _parse_ip_address(ipv4_candidate)
        if parsed is not None:
            extracted.append(parsed)

    for ipv6_candidate in BRACKET_IPV6_PATTERN.findall(value):
        parsed = _parse_ip_address(ipv6_candidate)
        if parsed is not None:
            extracted.append(parsed)

    return extracted


def _raw_ip_score(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
    """Score raw IP findings by address class."""
    if _is_non_public_ip(ip_address):
        return NET_RAW_IP_NON_PUBLIC_SCORE
    return NET_RAW_IP_PUBLIC_SCORE


def _raw_ip_description(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return a finding description based on raw IP type."""
    if _is_non_public_ip(ip_address):
        return "Configuration references a non-public raw IP address " f"({ip_address.compressed})."
    return "Configuration references a public raw IP address " f"({ip_address.compressed}), bypassing domain controls."


def _is_non_public_ip(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for private, loopback, reserved, or otherwise non-routable IPs."""
    return (
        ip_address.is_private
        or ip_address.is_loopback
        or ip_address.is_link_local
        or ip_address.is_multicast
        or ip_address.is_reserved
        or ip_address.is_unspecified
    )


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


def _levenshtein_distance(left: str, right: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous_row = list(range(len(right) + 1))
    for index_left, char_left in enumerate(left, start=1):
        current_row = [index_left]
        for index_right, char_right in enumerate(right, start=1):
            insert_cost = current_row[index_right - 1] + 1
            delete_cost = previous_row[index_right] + 1
            replace_cost = previous_row[index_right - 1] + (char_left != char_right)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row
    return previous_row[-1]


def _declared_name(parsed: ParsedSkillDocument) -> str | None:
    """Return frontmatter `name` field if present."""
    if isinstance(parsed.frontmatter, dict):
        name = parsed.frontmatter.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return None


_PROSE_MIN_WORDS: int = 3


def _looks_like_prose(value: str) -> bool:
    """Return True when the value appears to be natural-language prose.

    Prose lines contain spaces and multiple words — unlike encoded blobs,
    hex strings, or base64 payloads which are dense character sequences.
    """
    if " " not in value:
        return False
    words = value.split()
    return len(words) >= _PROSE_MIN_WORDS


# Patterns that look like env-var references but are API operators or
# non-secret variable names (e.g., MongoDB $set, Amplitude $add).
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

# Secret-like keywords that, when found in an env-var name, confirm it as
# a genuine secret reference.
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


def _is_non_secret_env_ref(value: str) -> bool:
    """Return True when env-var references in the value are non-secret operators."""
    for match in ENV_REF_PATTERN.finditer(value):
        ref = match.group(0).lower().strip("${} ")
        # Skip known operator patterns
        if ref in _NON_SECRET_ENV_OPERATORS:
            continue
        # Check if the reference contains a secret-like keyword
        if any(kw in ref for kw in _SECRET_ENV_KEYWORDS):
            return False
        # For ${VAR} and $VAR patterns, check if the var name is secret-like
        # If it doesn't match any secret keyword, treat it as non-secret
    return True


def _is_placeholder_secret_value(value: str) -> bool:
    return bool(SECRET_PLACEHOLDER_VALUE_PATTERN.search(value))
