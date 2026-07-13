"""Config fingerprinting for cache invalidation."""

from __future__ import annotations

import hashlib
import json

from razin.config.model import RazinConfig
from razin.constants.config import DEFAULT_DETECTORS


def effective_detector_ids(config: RazinConfig) -> tuple[str, ...]:
    """Resolve enabled detectors with config overrides."""
    enabled = list(config.detectors.enabled or DEFAULT_DETECTORS)
    disabled = set(config.detectors.disabled)
    resolved = [detector_id for detector_id in enabled if detector_id not in disabled]
    return tuple(resolved)


def config_fingerprint(config: RazinConfig, max_file_mb_override: int | None = None) -> str:
    """Return a stable hash fingerprint for cache invalidation."""
    payload = {
        "profile": config.profile,
        "allowlist_domains": list(config.allowlist_domains),
        "effective_allowlist_domains": list(config.effective_allowlist_domains),
        "ignore_default_allowlist": config.ignore_default_allowlist,
        "strict_subdomains": config.strict_subdomains,
        "denylist_domains": list(config.denylist_domains),
        "mcp_allowlist_domains": list(config.mcp_allowlist_domains),
        "mcp_denylist_domains": list(config.mcp_denylist_domains),
        "tool_prefixes": list(config.tool_prefixes),
        "detectors_enabled": list(config.detectors.enabled),
        "detectors_disabled": list(config.detectors.disabled),
        "effective_detectors": list(effective_detector_ids(config)),
        "typosquat_baseline": list(config.typosquat_baseline),
        "tool_tier_destructive": list(config.tool_tier_keywords.destructive),
        "tool_tier_write": list(config.tool_tier_keywords.write),
        "data_sensitivity_high_services": list(config.data_sensitivity.high_services),
        "data_sensitivity_medium_services": list(config.data_sensitivity.medium_services),
        "data_sensitivity_low_services": list(config.data_sensitivity.low_services),
        "data_sensitivity_high_keywords": list(config.data_sensitivity.high_keywords),
        "data_sensitivity_medium_keywords": list(config.data_sensitivity.medium_keywords),
        "data_sensitivity_service_categories": sorted((config.data_sensitivity.service_categories or {}).items()),
        "rule_overrides": sorted(
            (
                rule_id,
                override.enabled,
                override.max_severity,
                override.min_severity,
            )
            for rule_id, override in config.rule_overrides.items()
        ),
        "skill_globs": list(config.skill_globs),
        "max_file_mb": (max_file_mb_override if max_file_mb_override is not None else config.max_file_mb),
        "package_analysis": {
            "enabled": config.package_analysis.enabled,
            "max_files": config.package_analysis.max_files,
            "max_directories": config.package_analysis.max_directories,
            "max_total_mb": config.package_analysis.max_total_mb,
            "max_file_mb": config.package_analysis.max_file_mb,
            "max_findings_per_rule": config.package_analysis.max_findings_per_rule,
            "emit_inventory": config.package_analysis.emit_inventory,
            "known_bad_domains": list(config.package_analysis.known_bad.domains),
            "known_bad_sha256": list(config.package_analysis.known_bad.sha256),
            "known_bad_indicators": list(config.package_analysis.known_bad.indicators),
        },
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def package_analysis_fingerprint(
    config: RazinConfig,
    *,
    max_findings_per_rule_floor: int = 0,
) -> str:
    """Hash only configuration that can change whole-package analysis facts."""
    analysis = config.package_analysis
    payload = {
        "enabled": analysis.enabled,
        "max_files": analysis.max_files,
        "max_directories": analysis.max_directories,
        "max_total_mb": analysis.max_total_mb,
        "max_file_mb": analysis.max_file_mb,
        "effective_max_findings_per_rule": max(analysis.max_findings_per_rule, max_findings_per_rule_floor),
        "known_bad_domains": list(analysis.known_bad.domains),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
