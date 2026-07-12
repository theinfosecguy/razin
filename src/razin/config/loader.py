"""Config loading and normalization for Razin scans."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import yaml

from razin.config.model import RazinConfig
from razin.constants.config import (
    ALLOWED_QUIET_FORMATS,
    ALLOWED_QUIET_WRITE_MODES,
    CONFIG_FILENAME,
    DEFAULT_MAX_FILE_MB,
    DEFAULT_QUIET_MODE_ENABLED,
    DEFAULT_QUIET_MODE_FORMAT,
    DEFAULT_SKILL_GLOBS,
    DEFAULT_TOOL_PREFIXES_CONFIG,
    RULE_OVERRIDE_ALLOWED_KEYS,
    RULE_OVERRIDE_ALLOWED_SEVERITIES,
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
from razin.constants.package_analysis import (
    DEFAULT_PACKAGE_MAX_DIRECTORIES,
    DEFAULT_PACKAGE_MAX_FILE_MB,
    DEFAULT_PACKAGE_MAX_FILES,
    DEFAULT_PACKAGE_MAX_FINDINGS_PER_RULE,
    DEFAULT_PACKAGE_MAX_TOTAL_MB,
    MAX_IOC_ENTRIES_PER_KIND,
    MAX_IOC_INDICATOR_LENGTH,
)
from razin.constants.profiles import (
    DEFAULT_PROFILE,
    VALID_PROFILES,
)
from razin.constants.scoring import SEVERITY_RANK
from razin.exceptions import ConfigError
from razin.scanner.assessment import max_allowed_severity, signal_kind_for_rule
from razin.types import Severity
from razin.types.config import (
    DataSensitivityConfig,
    DetectorConfig,
    IocConfig,
    PackageAnalysisConfig,
    QuietModeConfig,
    RuleOverrideConfig,
    ToolTierConfig,
)


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

    max_file_mb = raw.get("max_file_mb", DEFAULT_MAX_FILE_MB)
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

    rule_overrides = _parse_rule_overrides(raw.get("rule_overrides"))

    quiet_mode = _build_quiet_mode_config(raw.get("quiet_mode", {}))
    package_analysis = _build_package_analysis_config(raw.get("package_analysis", {}))

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
        rule_overrides=rule_overrides,
        skill_globs=tuple(_ensure_string_list(raw.get("skill_globs", DEFAULT_SKILL_GLOBS), "skill_globs")),
        max_file_mb=max_file_mb,
        quiet_mode=quiet_mode,
        package_analysis=package_analysis,
    )


def _build_package_analysis_config(raw: Any) -> PackageAnalysisConfig:
    """Build deterministic package-analysis limits and operator IOC inputs."""
    if raw is None:
        return PackageAnalysisConfig()
    if not isinstance(raw, dict):
        raise ConfigError("package_analysis must be a mapping")

    enabled = raw.get("enabled", True)
    emit_inventory = raw.get("emit_inventory", False)
    if not isinstance(enabled, bool):
        raise ConfigError("package_analysis.enabled must be a boolean")
    if not isinstance(emit_inventory, bool):
        raise ConfigError("package_analysis.emit_inventory must be a boolean")

    known_bad_raw = raw.get("known_bad", {})
    if known_bad_raw is None:
        known_bad_raw = {}
    if not isinstance(known_bad_raw, dict):
        raise ConfigError("package_analysis.known_bad must be a mapping")

    sha256_values = tuple(
        sorted(
            {
                value.strip().lower()
                for value in _ensure_string_list(known_bad_raw.get("sha256", []), "package_analysis.known_bad.sha256")
                if value.strip()
            }
        )
    )
    invalid_hashes = [
        value for value in sha256_values if len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
    ]
    if invalid_hashes:
        raise ConfigError("package_analysis.known_bad.sha256 entries must be 64-character hexadecimal SHA-256 values")

    raw_domains = _ensure_string_list(known_bad_raw.get("domains", []), "package_analysis.known_bad.domains")
    invalid_domains = [domain for domain in raw_domains if not _is_domain_name(domain)]
    if invalid_domains:
        raise ConfigError("package_analysis.known_bad.domains entries must be plain DNS domain names")
    raw_indicators = _ensure_string_list(
        known_bad_raw.get("indicators", []),
        "package_analysis.known_bad.indicators",
    )
    for key, values in (("domains", raw_domains), ("sha256", list(sha256_values)), ("indicators", raw_indicators)):
        if len(values) > MAX_IOC_ENTRIES_PER_KIND:
            raise ConfigError(f"package_analysis.known_bad.{key} accepts at most {MAX_IOC_ENTRIES_PER_KIND} entries")
    invalid_indicators = [
        value for value in raw_indicators if len(value.strip()) < 4 or len(value.strip()) > MAX_IOC_INDICATOR_LENGTH
    ]
    if invalid_indicators:
        raise ConfigError(
            "package_analysis.known_bad.indicators entries must be between 4 and "
            f"{MAX_IOC_INDICATOR_LENGTH} characters"
        )

    return PackageAnalysisConfig(
        enabled=enabled,
        max_files=_positive_int(raw.get("max_files", DEFAULT_PACKAGE_MAX_FILES), "package_analysis.max_files"),
        max_directories=_positive_int(
            raw.get("max_directories", DEFAULT_PACKAGE_MAX_DIRECTORIES),
            "package_analysis.max_directories",
        ),
        max_total_mb=_positive_int(
            raw.get("max_total_mb", DEFAULT_PACKAGE_MAX_TOTAL_MB),
            "package_analysis.max_total_mb",
        ),
        max_file_mb=_positive_int(raw.get("max_file_mb", DEFAULT_PACKAGE_MAX_FILE_MB), "package_analysis.max_file_mb"),
        max_findings_per_rule=_positive_int(
            raw.get("max_findings_per_rule", DEFAULT_PACKAGE_MAX_FINDINGS_PER_RULE),
            "package_analysis.max_findings_per_rule",
        ),
        emit_inventory=emit_inventory,
        known_bad=IocConfig(
            domains=_normalize_domains(raw_domains),
            sha256=sha256_values,
            indicators=tuple(sorted({value.strip() for value in raw_indicators if value.strip()})),
        ),
    )


def _positive_int(value: Any, key_name: str) -> int:
    """Validate a positive integer without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{key_name} must be a positive integer")
    return value


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


def _is_domain_name(value: str) -> bool:
    domain = value.strip().lower().rstrip(".")
    if len(domain) > 253 or "." not in domain:
        return False
    return (
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", domain)
        is not None
    )


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


def _parse_rule_overrides(raw: Any) -> dict[str, RuleOverrideConfig]:
    """Parse and validate the optional ``rule_overrides`` config block."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("rule_overrides must be a mapping")

    overrides: dict[str, RuleOverrideConfig] = {}
    for rule_id, override_raw in raw.items():
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ConfigError("rule_overrides keys must be non-empty rule id strings")
        if not isinstance(override_raw, dict):
            raise ConfigError(f"rule_overrides.{rule_id} must be a mapping")

        unknown_keys = set(override_raw) - RULE_OVERRIDE_ALLOWED_KEYS
        if unknown_keys:
            raise ConfigError(
                f"rule_overrides.{rule_id} has unsupported keys: {', '.join(sorted(unknown_keys))}. "
                f"Supported keys: {', '.join(sorted(RULE_OVERRIDE_ALLOWED_KEYS))}"
            )

        enabled = override_raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"rule_overrides.{rule_id}.enabled must be a boolean")

        max_severity = _parse_override_severity(
            rule_id=rule_id,
            key="max_severity",
            value=override_raw.get("max_severity"),
        )
        min_severity = _parse_override_severity(
            rule_id=rule_id,
            key="min_severity",
            value=override_raw.get("min_severity"),
        )
        if (
            max_severity is not None
            and min_severity is not None
            and SEVERITY_RANK[min_severity] > SEVERITY_RANK[max_severity]
        ):
            raise ConfigError(
                f"rule_overrides.{rule_id} is contradictory: min_severity {min_severity!r} "
                f"is higher than max_severity {max_severity!r}"
            )
        if min_severity is not None:
            signal_maximum = max_allowed_severity(signal_kind_for_rule(rule_id))
            if SEVERITY_RANK[min_severity] > SEVERITY_RANK[signal_maximum]:
                raise ConfigError(
                    f"rule_overrides.{rule_id}.min_severity {min_severity!r} exceeds the "
                    f"{signal_maximum!r} maximum supported by this rule's evidence kind"
                )

        overrides[rule_id] = RuleOverrideConfig(enabled=enabled, max_severity=max_severity, min_severity=min_severity)

    return overrides


def _parse_override_severity(
    *,
    rule_id: str,
    key: str,
    value: Any,
) -> Severity | None:
    """Parse a severity override value from rule_overrides."""
    if value is None:
        return None
    if not isinstance(value, str) or value not in RULE_OVERRIDE_ALLOWED_SEVERITIES:
        raise ConfigError(
            f"rule_overrides.{rule_id}.{key} must be one of {', '.join(sorted(RULE_OVERRIDE_ALLOWED_SEVERITIES))}"
        )
    return cast(Severity, value)


def _build_quiet_mode_config(raw: Any) -> QuietModeConfig:
    """Build a QuietModeConfig from the raw quiet_mode YAML block."""
    if raw is None:
        return QuietModeConfig()
    if not isinstance(raw, dict):
        raise ConfigError("quiet_mode must be a mapping")

    enabled = raw.get("enabled", DEFAULT_QUIET_MODE_ENABLED)
    if not isinstance(enabled, bool):
        raise ConfigError("quiet_mode.enabled must be a boolean")

    output_path = raw.get("output_path")
    if output_path is not None and not isinstance(output_path, str):
        raise ConfigError("quiet_mode.output_path must be a string")

    fmt = raw.get("format", DEFAULT_QUIET_MODE_FORMAT)
    if not isinstance(fmt, str) or fmt not in ALLOWED_QUIET_FORMATS:
        raise ConfigError(f"quiet_mode.format must be one of {', '.join(sorted(ALLOWED_QUIET_FORMATS))}")

    include_warnings = raw.get("include_warnings", True)
    if not isinstance(include_warnings, bool):
        raise ConfigError("quiet_mode.include_warnings must be a boolean")

    include_summary = raw.get("include_summary", True)
    if not isinstance(include_summary, bool):
        raise ConfigError("quiet_mode.include_summary must be a boolean")

    write_mode = raw.get("write_mode", "overwrite")
    if not isinstance(write_mode, str) or write_mode not in ALLOWED_QUIET_WRITE_MODES:
        raise ConfigError(f"quiet_mode.write_mode must be one of {', '.join(sorted(ALLOWED_QUIET_WRITE_MODES))}")

    if enabled and not output_path:
        raise ConfigError("quiet_mode.output_path is required when quiet_mode.enabled is true")

    return QuietModeConfig(
        enabled=enabled,
        output_path=output_path,
        format=fmt,  # type: ignore[arg-type]
        include_warnings=include_warnings,
        include_summary=include_summary,
        write_mode=write_mode,  # type: ignore[arg-type]
    )
