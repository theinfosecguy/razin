"""Config loading and normalization for Razin scans."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from razin.config.model import RazinConfig, _merge_domains
from razin.constants.config import (
    CONFIG_FILENAME,
    DEFAULT_SKILL_GLOBS,
    DEFAULT_TOOL_PREFIXES_CONFIG,
)
from razin.constants.data_sensitivity import (
    HIGH_SENSITIVITY_KEYWORDS,
    HIGH_SENSITIVITY_SERVICES,
    LOW_SENSITIVITY_SERVICES,
    MEDIUM_SENSITIVITY_KEYWORDS,
    MEDIUM_SENSITIVITY_SERVICES,
)
from razin.constants.docs import (
    TOOL_TIER_DESTRUCTIVE_KEYWORDS,
    TOOL_TIER_WRITE_KEYWORDS,
)
from razin.constants.profiles import (
    DEFAULT_PROFILE,
    VALID_PROFILES,
)
from razin.exceptions import ConfigError
from razin.types.config import DataSensitivityConfig, DetectorConfig, ToolTierConfig


def load_config(root: Path, config_path: Path | None = None) -> RazinConfig:
    """Load and validate scanner config from ``razin.yaml`` or an explicit path."""
    root = root.resolve()
    path = config_path.resolve() if config_path else (root / CONFIG_FILENAME)
    if not path.exists():
        if config_path is not None:
            raise ConfigError(f"Config file not found: {path}")
        return RazinConfig()

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

    tool_tier_raw = raw.get("tool_tier_keywords", {})
    if tool_tier_raw is None:
        tool_tier_raw = {}
    if not isinstance(tool_tier_raw, dict):
        raise ConfigError("tool_tier_keywords must be a mapping")

    data_sensitivity_raw = raw.get("data_sensitivity", {})
    if data_sensitivity_raw is None:
        data_sensitivity_raw = {}
    if not isinstance(data_sensitivity_raw, dict):
        raise ConfigError("data_sensitivity must be a mapping")

    tool_tier = ToolTierConfig(
        destructive=tuple(
            kw.upper()
            for kw in _ensure_string_list(
                tool_tier_raw.get("destructive", list(TOOL_TIER_DESTRUCTIVE_KEYWORDS)),
                "tool_tier_keywords.destructive",
            )
            if kw.strip()
        ),
        write=tuple(
            kw.upper()
            for kw in _ensure_string_list(
                tool_tier_raw.get("write", list(TOOL_TIER_WRITE_KEYWORDS)),
                "tool_tier_keywords.write",
            )
            if kw.strip()
        ),
    )

    max_file_mb = raw.get("max_file_mb", 10)
    if isinstance(max_file_mb, bool) or not isinstance(max_file_mb, int) or max_file_mb <= 0:
        raise ConfigError("max_file_mb must be a positive integer")

    profile_raw = raw.get("profile", DEFAULT_PROFILE)
    if not isinstance(profile_raw, str) or profile_raw not in VALID_PROFILES:
        raise ConfigError(f"profile must be one of {sorted(VALID_PROFILES)}, got {profile_raw!r}")

    ignore_default_allowlist = raw.get("ignore_default_allowlist", False)
    if not isinstance(ignore_default_allowlist, bool):
        raise ConfigError("ignore_default_allowlist must be a boolean")

    strict_subdomains = raw.get("strict_subdomains", False)
    if not isinstance(strict_subdomains, bool):
        raise ConfigError("strict_subdomains must be a boolean")

    return RazinConfig(
        profile=profile_raw,  # type: ignore[arg-type]
        allowlist_domains=_normalize_domains(
            _ensure_string_list(raw.get("allowlist_domains", []), "allowlist_domains")
        ),
        ignore_default_allowlist=ignore_default_allowlist,
        strict_subdomains=strict_subdomains,
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
        tool_tier_keywords=tool_tier,
        data_sensitivity=_build_data_sensitivity_config(data_sensitivity_raw),
        skill_globs=tuple(_ensure_string_list(raw.get("skill_globs", DEFAULT_SKILL_GLOBS), "skill_globs")),
        max_file_mb=max_file_mb,
    )


def _ensure_string_list(value: Any, key_name: str) -> list[str]:
    """Coerce a value to a list of strings, raising ConfigError on type mismatch."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key_name} must be a list of strings")
    return list(value)


def _normalize_domains(domains: list[str]) -> tuple[str, ...]:
    """Lowercase, strip, deduplicate and sort a list of domain strings."""
    normalized = [domain.strip().lower() for domain in domains if domain.strip()]
    return tuple(sorted(set(normalized)))


def _build_data_sensitivity_config(raw: dict[str, Any]) -> DataSensitivityConfig:
    """Build a DataSensitivityConfig from the raw data_sensitivity YAML block."""
    high_services = tuple(
        s.lower()
        for s in _ensure_string_list(
            raw.get("high_services", list(HIGH_SENSITIVITY_SERVICES)),
            "data_sensitivity.high_services",
        )
        if s.strip()
    )
    medium_services = tuple(
        s.lower()
        for s in _ensure_string_list(
            raw.get("medium_services", list(MEDIUM_SENSITIVITY_SERVICES)),
            "data_sensitivity.medium_services",
        )
        if s.strip()
    )
    low_services = tuple(
        s.lower()
        for s in _ensure_string_list(
            raw.get("low_services", list(LOW_SENSITIVITY_SERVICES)),
            "data_sensitivity.low_services",
        )
        if s.strip()
    )
    high_keywords = tuple(
        k.lower()
        for k in _ensure_string_list(
            raw.get("high_keywords", list(HIGH_SENSITIVITY_KEYWORDS)),
            "data_sensitivity.high_keywords",
        )
        if k.strip()
    )
    medium_keywords = tuple(
        k.lower()
        for k in _ensure_string_list(
            raw.get("medium_keywords", list(MEDIUM_SENSITIVITY_KEYWORDS)),
            "data_sensitivity.medium_keywords",
        )
        if k.strip()
    )

    service_categories_raw = raw.get("service_categories")
    service_categories: dict[str, str] | None = None
    if service_categories_raw is not None:
        if not isinstance(service_categories_raw, dict):
            raise ConfigError("data_sensitivity.service_categories must be a mapping")
        service_categories = {str(k).lower(): str(v) for k, v in service_categories_raw.items()}

    return DataSensitivityConfig(
        high_services=high_services,
        medium_services=medium_services,
        low_services=low_services,
        high_keywords=high_keywords,
        medium_keywords=medium_keywords,
        service_categories=service_categories,
    )
