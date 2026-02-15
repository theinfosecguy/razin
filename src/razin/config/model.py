"""Config data model for Razin scans."""

from __future__ import annotations

from dataclasses import dataclass

from razin.constants.config import (
    DEFAULT_MAX_FILE_MB,
    DEFAULT_SKILL_GLOBS,
    DEFAULT_TOOL_PREFIXES_CONFIG,
)
from razin.constants.domains import DEFAULT_ALLOWLISTED_DOMAINS
from razin.constants.profiles import (
    DEFAULT_PROFILE,
    PROFILE_AGGREGATE_MIN_SCORE,
    PROFILE_HIGH_SEVERITY_MIN,
    PROFILE_MEDIUM_SEVERITY_MIN,
    PROFILE_SUPPRESS_LOCAL_HOSTS,
    ProfileName,
)
from razin.types.config import DataSensitivityConfig, DetectorConfig, ToolTierConfig


def _merge_domains(*domain_sets: tuple[str, ...]) -> tuple[str, ...]:
    """Merge and sort multiple domain tuples into a single deduplicated tuple."""
    merged: set[str] = set()
    for domains in domain_sets:
        merged.update(domains)
    return tuple(sorted(merged))


@dataclass(frozen=True)
class RazinConfig:
    """Resolved scanner config."""

    profile: ProfileName = DEFAULT_PROFILE
    allowlist_domains: tuple[str, ...] = ()
    ignore_default_allowlist: bool = False
    strict_subdomains: bool = False
    denylist_domains: tuple[str, ...] = ()
    mcp_allowlist_domains: tuple[str, ...] = ()
    mcp_denylist_domains: tuple[str, ...] = ()
    tool_prefixes: tuple[str, ...] = DEFAULT_TOOL_PREFIXES_CONFIG
    detectors: DetectorConfig = DetectorConfig()
    tool_tier_keywords: ToolTierConfig = ToolTierConfig()
    data_sensitivity: DataSensitivityConfig = DataSensitivityConfig()
    typosquat_baseline: tuple[str, ...] = ()
    skill_globs: tuple[str, ...] = DEFAULT_SKILL_GLOBS
    max_file_mb: int = DEFAULT_MAX_FILE_MB

    @property
    def aggregate_min_rule_score(self) -> int:
        """Minimum per-rule score to contribute to the aggregate."""
        return PROFILE_AGGREGATE_MIN_SCORE.get(self.profile, PROFILE_AGGREGATE_MIN_SCORE[DEFAULT_PROFILE])

    @property
    def suppress_local_hosts(self) -> bool:
        """Whether to suppress local/dev hosts in domain detectors."""
        return PROFILE_SUPPRESS_LOCAL_HOSTS.get(self.profile, True)

    @property
    def effective_allowlist_domains(self) -> tuple[str, ...]:
        """Domain allowlist used by detectors after applying defaults."""
        if self.ignore_default_allowlist:
            return self.allowlist_domains
        return _merge_domains(DEFAULT_ALLOWLISTED_DOMAINS, self.allowlist_domains)

    @property
    def high_severity_min(self) -> int:
        """Minimum aggregate score for high severity under this profile."""
        return PROFILE_HIGH_SEVERITY_MIN.get(self.profile, 70)

    @property
    def medium_severity_min(self) -> int:
        """Minimum aggregate score for medium severity under this profile."""
        return PROFILE_MEDIUM_SEVERITY_MIN.get(self.profile, 40)
