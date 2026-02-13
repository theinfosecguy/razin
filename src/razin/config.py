"""Configuration loading and normalization for Raisin scans."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from razin.constants.config import (
    CONFIG_FILENAME,
    DEFAULT_DETECTORS,
    DEFAULT_MAX_FILE_MB,
    DEFAULT_SKILL_GLOBS,
    DEFAULT_TOOL_PREFIXES_CONFIG,
)
from razin.constants.profiles import (
    DEFAULT_PROFILE,
    PROFILE_AGGREGATE_MIN_SCORE,
    PROFILE_HIGH_SEVERITY_MIN,
    PROFILE_MEDIUM_SEVERITY_MIN,
    PROFILE_SUPPRESS_LOCAL_HOSTS,
    VALID_PROFILES,
    ProfileName,
)
from razin.exceptions import ConfigError


@dataclass(frozen=True)
class DetectorConfig:
    """Detector enablement toggles."""

    enabled: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()


@dataclass(frozen=True)
class RaisinConfig:
    """Resolved scanner config."""

    profile: ProfileName = DEFAULT_PROFILE
    allowlist_domains: tuple[str, ...] = ()
    denylist_domains: tuple[str, ...] = ()
    mcp_allowlist_domains: tuple[str, ...] = ()
    mcp_denylist_domains: tuple[str, ...] = ()
    tool_prefixes: tuple[str, ...] = DEFAULT_TOOL_PREFIXES_CONFIG
    detectors: DetectorConfig = DetectorConfig()
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
    def high_severity_min(self) -> int:
        """Minimum aggregate score for high severity under this profile."""
        return PROFILE_HIGH_SEVERITY_MIN.get(self.profile, 70)

    @property
    def medium_severity_min(self) -> int:
        """Minimum aggregate score for medium severity under this profile."""
        return PROFILE_MEDIUM_SEVERITY_MIN.get(self.profile, 40)


def load_config(root: Path, config_path: Path | None = None) -> RaisinConfig:
    """Load and validate scanner config from `razin.yaml` or an explicit path."""
    root = root.resolve()
    path = config_path.resolve() if config_path else (root / CONFIG_FILENAME)
    if not path.exists():
        return RaisinConfig()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML config file at {path}: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file at {path} must be a YAML mapping")

    detectors_raw = raw.get("detectors", {})
    if detectors_raw is None:
        detectors_raw = {}
    if not isinstance(detectors_raw, dict):
        raise ConfigError("detectors must be a mapping")

    typosquat_raw = raw.get("typosquat", {})
    if typosquat_raw is None:
        typosquat_raw = {}
    if not isinstance(typosquat_raw, dict):
        raise ConfigError("typosquat must be a mapping")

    max_file_mb = raw.get("max_file_mb", DEFAULT_MAX_FILE_MB)
    if isinstance(max_file_mb, bool) or not isinstance(max_file_mb, int) or max_file_mb <= 0:
        raise ConfigError("max_file_mb must be a positive integer")

    profile_raw = raw.get("profile", DEFAULT_PROFILE)
    if not isinstance(profile_raw, str) or profile_raw not in VALID_PROFILES:
        raise ConfigError(f"profile must be one of {sorted(VALID_PROFILES)}, got {profile_raw!r}")

    return RaisinConfig(
        profile=profile_raw,  # type: ignore[arg-type]
        allowlist_domains=_normalize_domains(
            _ensure_string_list(raw.get("allowlist_domains", []), "allowlist_domains")
        ),
        denylist_domains=_normalize_domains(_ensure_string_list(raw.get("denylist_domains", []), "denylist_domains")),
        mcp_allowlist_domains=_normalize_domains(
            _ensure_string_list(raw.get("mcp_allowlist_domains", []), "mcp_allowlist_domains")
        ),
        mcp_denylist_domains=_normalize_domains(
            _ensure_string_list(raw.get("mcp_denylist_domains", []), "mcp_denylist_domains")
        ),
        tool_prefixes=tuple(
            prefix.upper()
            for prefix in _ensure_string_list(
                raw.get("tool_prefixes", list(DEFAULT_TOOL_PREFIXES_CONFIG)),
                "tool_prefixes",
            )
            if prefix.strip()
        ),
        detectors=DetectorConfig(
            enabled=tuple(_ensure_string_list(detectors_raw.get("enabled", []), "detectors.enabled")),
            disabled=tuple(_ensure_string_list(detectors_raw.get("disabled", []), "detectors.disabled")),
        ),
        typosquat_baseline=tuple(_ensure_string_list(typosquat_raw.get("baseline", []), "typosquat.baseline")),
        skill_globs=tuple(_ensure_string_list(raw.get("skill_globs", DEFAULT_SKILL_GLOBS), "skill_globs")),
        max_file_mb=max_file_mb,
    )


def effective_detector_ids(config: RaisinConfig) -> tuple[str, ...]:
    """Resolve enabled detectors with config overrides."""
    enabled = list(config.detectors.enabled or DEFAULT_DETECTORS)
    disabled = set(config.detectors.disabled)
    resolved = [detector_id for detector_id in enabled if detector_id not in disabled]
    return tuple(resolved)


def config_fingerprint(config: RaisinConfig, max_file_mb_override: int | None = None) -> str:
    """Return a stable hash fingerprint for cache invalidation."""
    payload = {
        "profile": config.profile,
        "allowlist_domains": list(config.allowlist_domains),
        "denylist_domains": list(config.denylist_domains),
        "mcp_allowlist_domains": list(config.mcp_allowlist_domains),
        "mcp_denylist_domains": list(config.mcp_denylist_domains),
        "tool_prefixes": list(config.tool_prefixes),
        "detectors_enabled": list(config.detectors.enabled),
        "detectors_disabled": list(config.detectors.disabled),
        "effective_detectors": list(effective_detector_ids(config)),
        "typosquat_baseline": list(config.typosquat_baseline),
        "skill_globs": list(config.skill_globs),
        "max_file_mb": (max_file_mb_override if max_file_mb_override is not None else config.max_file_mb),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _ensure_string_list(value: Any, key_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key_name} must be a list of strings")
    return list(value)


def _normalize_domains(domains: list[str]) -> tuple[str, ...]:
    normalized = [domain.strip().lower() for domain in domains if domain.strip()]
    return tuple(sorted(set(normalized)))
