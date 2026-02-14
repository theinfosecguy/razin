"""Configuration loading and normalization for Razin scans."""

from __future__ import annotations

import difflib
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
from razin.constants.docs import (
    TOOL_TIER_DESTRUCTIVE_KEYWORDS,
    TOOL_TIER_WRITE_KEYWORDS,
)
from razin.constants.domains import DEFAULT_ALLOWLISTED_DOMAINS
from razin.constants.profiles import (
    DEFAULT_PROFILE,
    PROFILE_AGGREGATE_MIN_SCORE,
    PROFILE_HIGH_SEVERITY_MIN,
    PROFILE_MEDIUM_SEVERITY_MIN,
    PROFILE_SUPPRESS_LOCAL_HOSTS,
    VALID_PROFILES,
    ProfileName,
)
from razin.constants.validation import (
    ALLOWED_CONFIG_KEYS,
    ALLOWED_DETECTOR_KEYS,
    ALLOWED_TOOL_TIER_KEYS,
    ALLOWED_TYPOSQUAT_KEYS,
    CFG001,
    CFG002,
    CFG003,
    CFG004,
    CFG005,
    CFG006,
    CFG007,
    CFG008,
    CFG009,
    LIST_OF_STRINGS_KEYS,
)
from razin.exceptions import ConfigError
from razin.exceptions.validation import ValidationError


@dataclass(frozen=True)
class ToolTierConfig:
    """Keyword tiers for tool token risk classification."""

    destructive: tuple[str, ...] = TOOL_TIER_DESTRUCTIVE_KEYWORDS
    write: tuple[str, ...] = TOOL_TIER_WRITE_KEYWORDS


@dataclass(frozen=True)
class DetectorConfig:
    """Detector enablement toggles."""

    enabled: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()


@dataclass(frozen=True)
class RazinConfig:
    """Resolved scanner config."""

    profile: ProfileName = DEFAULT_PROFILE
    allowlist_domains: tuple[str, ...] = ()
    ignore_default_allowlist: bool = False
    denylist_domains: tuple[str, ...] = ()
    mcp_allowlist_domains: tuple[str, ...] = ()
    mcp_denylist_domains: tuple[str, ...] = ()
    tool_prefixes: tuple[str, ...] = DEFAULT_TOOL_PREFIXES_CONFIG
    detectors: DetectorConfig = DetectorConfig()
    tool_tier_keywords: ToolTierConfig = ToolTierConfig()
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


def load_config(root: Path, config_path: Path | None = None) -> RazinConfig:
    """Load and validate scanner config from `razin.yaml` or an explicit path."""
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

    return RazinConfig(
        profile=profile_raw,  # type: ignore[arg-type]
        allowlist_domains=_normalize_domains(
            _ensure_string_list(raw.get("allowlist_domains", []), "allowlist_domains")
        ),
        ignore_default_allowlist=ignore_default_allowlist,
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
        skill_globs=tuple(_ensure_string_list(raw.get("skill_globs", DEFAULT_SKILL_GLOBS), "skill_globs")),
        max_file_mb=max_file_mb,
    )


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


def _merge_domains(*domain_sets: tuple[str, ...]) -> tuple[str, ...]:
    merged: set[str] = set()
    for domains in domain_sets:
        merged.update(domains)
    return tuple(sorted(merged))


def validate_config_file(
    root: Path,
    config_path: Path | None = None,
    *,
    config_explicit: bool = False,
) -> list[ValidationError]:
    """Validate a razin.yaml file and return all validation errors.

    This is the collect-all entry point used by both ``razin validate-config``
    and ``razin scan`` preflight.  It never raises — all problems are returned
    as :class:`ValidationError` instances.
    """
    errors: list[ValidationError] = []
    root = root.resolve()
    path = config_path.resolve() if config_path else (root / CONFIG_FILENAME)
    path_str = str(path)

    if not path.exists():
        if config_explicit:
            errors.append(
                ValidationError(
                    code=CFG001,
                    path=path_str,
                    field="",
                    message=f"config file not found: {path}",
                )
            )
        return errors  # missing default → use defaults, no errors

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        errors.append(
            ValidationError(
                code=CFG002,
                path=path_str,
                field="",
                message=f"invalid YAML: {exc}",
            )
        )
        return errors

    if raw is None:
        return errors  # empty file → valid, defaults apply

    if not isinstance(raw, dict):
        errors.append(
            ValidationError(
                code=CFG003,
                path=path_str,
                field="",
                message=f"config must be a YAML mapping, got {type(raw).__name__}",
            )
        )
        return errors

    for key in sorted(raw.keys()):
        if key not in ALLOWED_CONFIG_KEYS:
            errors.append(
                ValidationError(
                    code=CFG004,
                    path=path_str,
                    field=key,
                    message=f"unknown key `{key}`",
                    hint=_suggest_key(key, ALLOWED_CONFIG_KEYS),
                )
            )

    if "profile" in raw:
        val = raw["profile"]
        if not isinstance(val, str) or val not in VALID_PROFILES:
            errors.append(
                ValidationError(
                    code=CFG006,
                    path=path_str,
                    field="profile",
                    message="invalid value for `profile`",
                    hint=f"expected one of: {', '.join(sorted(VALID_PROFILES))}; got: {val!r}",
                )
            )

    if "max_file_mb" in raw:
        val = raw["max_file_mb"]
        if isinstance(val, bool) or not isinstance(val, int):
            errors.append(
                ValidationError(
                    code=CFG005,
                    path=path_str,
                    field="max_file_mb",
                    message="invalid type for `max_file_mb`",
                    hint="expected a positive integer",
                )
            )
        elif val <= 0:
            errors.append(
                ValidationError(
                    code=CFG007,
                    path=path_str,
                    field="max_file_mb",
                    message=f"`max_file_mb` must be a positive integer, got {val}",
                )
            )

    if "ignore_default_allowlist" in raw:
        val = raw["ignore_default_allowlist"]
        if not isinstance(val, bool):
            errors.append(
                ValidationError(
                    code=CFG005,
                    path=path_str,
                    field="ignore_default_allowlist",
                    message="invalid type for `ignore_default_allowlist`",
                    hint="expected a boolean",
                )
            )

    for key in LIST_OF_STRINGS_KEYS:
        if key in raw:
            val = raw[key]
            if val is not None and (not isinstance(val, (list, tuple)) or not all(isinstance(i, str) for i in val)):
                errors.append(
                    ValidationError(
                        code=CFG005,
                        path=path_str,
                        field=key,
                        message=f"invalid type for `{key}`",
                        hint="expected a list of strings",
                    )
                )

    _validate_detectors_block(raw, path_str, errors)
    _validate_typosquat_block(raw, path_str, errors)
    _validate_tool_tier_block(raw, path_str, errors)

    return errors


def _validate_detectors_block(
    raw: dict[str, Any],
    path_str: str,
    errors: list[ValidationError],
) -> None:
    """Validate the ``detectors`` nested mapping in razin.yaml."""
    if "detectors" not in raw:
        return
    det = raw["detectors"]
    if det is None:
        return
    if not isinstance(det, dict):
        errors.append(
            ValidationError(
                code=CFG009,
                path=path_str,
                field="detectors",
                message="`detectors` must be a mapping",
            )
        )
        return

    # Unknown sub-keys
    for key in sorted(det.keys()):
        if key not in ALLOWED_DETECTOR_KEYS:
            errors.append(
                ValidationError(
                    code=CFG004,
                    path=path_str,
                    field=f"detectors.{key}",
                    message=f"unknown key `{key}` in `detectors`",
                    hint=_suggest_key(key, ALLOWED_DETECTOR_KEYS),
                )
            )

    # Type checks
    for sub_key in ("enabled", "disabled"):
        if sub_key in det:
            val = det[sub_key]
            if val is not None and (not isinstance(val, (list, tuple)) or not all(isinstance(i, str) for i in val)):
                errors.append(
                    ValidationError(
                        code=CFG005,
                        path=path_str,
                        field=f"detectors.{sub_key}",
                        message=f"invalid type for `detectors.{sub_key}`",
                        hint="expected a list of strings",
                    )
                )

    # Contradictory config
    enabled = det.get("enabled") or []
    disabled = det.get("disabled") or []
    if isinstance(enabled, list) and isinstance(disabled, list):
        overlap = sorted(set(enabled) & set(disabled))
        if overlap:
            errors.append(
                ValidationError(
                    code=CFG008,
                    path=path_str,
                    field="detectors",
                    message=f"detector(s) in both enabled and disabled: {', '.join(overlap)}",
                    hint="remove duplicates from one list",
                )
            )


def _validate_typosquat_block(
    raw: dict[str, Any],
    path_str: str,
    errors: list[ValidationError],
) -> None:
    """Validate the ``typosquat`` nested mapping in razin.yaml."""
    if "typosquat" not in raw:
        return
    typo = raw["typosquat"]
    if typo is None:
        return
    if not isinstance(typo, dict):
        errors.append(
            ValidationError(
                code=CFG009,
                path=path_str,
                field="typosquat",
                message="`typosquat` must be a mapping",
            )
        )
        return

    for key in sorted(typo.keys()):
        if key not in ALLOWED_TYPOSQUAT_KEYS:
            errors.append(
                ValidationError(
                    code=CFG004,
                    path=path_str,
                    field=f"typosquat.{key}",
                    message=f"unknown key `{key}` in `typosquat`",
                    hint=_suggest_key(key, ALLOWED_TYPOSQUAT_KEYS),
                )
            )

    if "baseline" in typo:
        val = typo["baseline"]
        if val is not None and (not isinstance(val, (list, tuple)) or not all(isinstance(i, str) for i in val)):
            errors.append(
                ValidationError(
                    code=CFG005,
                    path=path_str,
                    field="typosquat.baseline",
                    message="invalid type for `typosquat.baseline`",
                    hint="expected a list of strings",
                )
            )


def _validate_tool_tier_block(
    raw: dict[str, Any],
    path_str: str,
    errors: list[ValidationError],
) -> None:
    """Validate the ``tool_tier_keywords`` nested mapping in razin.yaml."""
    if "tool_tier_keywords" not in raw:
        return
    tier = raw["tool_tier_keywords"]
    if tier is None:
        return
    if not isinstance(tier, dict):
        errors.append(
            ValidationError(
                code=CFG009,
                path=path_str,
                field="tool_tier_keywords",
                message="`tool_tier_keywords` must be a mapping",
            )
        )
        return

    for key in sorted(tier.keys()):
        if key not in ALLOWED_TOOL_TIER_KEYS:
            errors.append(
                ValidationError(
                    code=CFG004,
                    path=path_str,
                    field=f"tool_tier_keywords.{key}",
                    message=f"unknown key `{key}` in `tool_tier_keywords`",
                    hint=_suggest_key(key, ALLOWED_TOOL_TIER_KEYS),
                )
            )

    for sub_key in ("destructive", "write"):
        if sub_key in tier:
            val = tier[sub_key]
            if val is not None and (
                not isinstance(val, (list, tuple)) or not all(isinstance(i, str) for i in val)
            ):
                errors.append(
                    ValidationError(
                        code=CFG005,
                        path=path_str,
                        field=f"tool_tier_keywords.{sub_key}",
                        message=f"invalid type for `tool_tier_keywords.{sub_key}`",
                        hint="expected a list of strings",
                    )
                )


def _suggest_key(unknown: str, allowed: frozenset[str]) -> str:
    """Return a 'did you mean …' hint for a close key match, or empty string."""
    matches = difflib.get_close_matches(unknown, sorted(allowed), n=1, cutoff=0.6)
    if matches:
        return f"did you mean `{matches[0]}`?"
    return ""
