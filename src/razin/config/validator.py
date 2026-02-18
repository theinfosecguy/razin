"""Config file validation for Razin scans."""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

import yaml

from razin.constants.config import CONFIG_FILENAME, RULE_OVERRIDE_ALLOWED_SEVERITIES
from razin.constants.profiles import VALID_PROFILES
from razin.constants.scoring import SEVERITY_RANK
from razin.constants.validation import (
    ALLOWED_CONFIG_KEYS,
    ALLOWED_DATA_SENSITIVITY_KEYS,
    ALLOWED_DETECTOR_KEYS,
    ALLOWED_RULE_OVERRIDE_KEYS,
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
from razin.exceptions.validation import ValidationError


def validate_config_file(
    root: Path,
    config_path: Path | None = None,
    *,
    config_explicit: bool = False,
) -> list[ValidationError]:
    """Validate a razin.yaml file and return all validation errors.

    This is the collect-all entry point used by both ``razin validate-config``
    and ``razin scan`` preflight.  It never raises; all problems are returned
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
        return errors

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
        return errors

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

    if "strict_subdomains" in raw:
        val = raw["strict_subdomains"]
        if not isinstance(val, bool):
            errors.append(
                ValidationError(
                    code=CFG005,
                    path=path_str,
                    field="strict_subdomains",
                    message="invalid type for `strict_subdomains`",
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
    _validate_data_sensitivity_block(raw, path_str, errors)
    _validate_rule_overrides_block(raw, path_str, errors)

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
            if val is not None and (not isinstance(val, (list, tuple)) or not all(isinstance(i, str) for i in val)):
                errors.append(
                    ValidationError(
                        code=CFG005,
                        path=path_str,
                        field=f"tool_tier_keywords.{sub_key}",
                        message=f"invalid type for `tool_tier_keywords.{sub_key}`",
                        hint="expected a list of strings",
                    )
                )


def _validate_data_sensitivity_block(
    raw: dict[str, Any],
    path_str: str,
    errors: list[ValidationError],
) -> None:
    """Validate the ``data_sensitivity`` nested mapping in razin.yaml."""
    if "data_sensitivity" not in raw:
        return
    ds = raw["data_sensitivity"]
    if ds is None:
        return
    if not isinstance(ds, dict):
        errors.append(
            ValidationError(
                code=CFG009,
                path=path_str,
                field="data_sensitivity",
                message="`data_sensitivity` must be a mapping",
            )
        )
        return

    for key in sorted(ds.keys()):
        if key not in ALLOWED_DATA_SENSITIVITY_KEYS:
            errors.append(
                ValidationError(
                    code=CFG004,
                    path=path_str,
                    field=f"data_sensitivity.{key}",
                    message=f"unknown key `{key}` in `data_sensitivity`",
                    hint=_suggest_key(key, ALLOWED_DATA_SENSITIVITY_KEYS),
                )
            )

    for sub_key in ("high_services", "medium_services", "low_services", "high_keywords", "medium_keywords"):
        if sub_key in ds:
            val = ds[sub_key]
            if val is not None and (not isinstance(val, (list, tuple)) or not all(isinstance(i, str) for i in val)):
                errors.append(
                    ValidationError(
                        code=CFG005,
                        path=path_str,
                        field=f"data_sensitivity.{sub_key}",
                        message=f"invalid type for `data_sensitivity.{sub_key}`",
                        hint="expected a list of strings",
                    )
                )

    if "service_categories" in ds:
        val = ds["service_categories"]
        if val is not None and not isinstance(val, dict):
            errors.append(
                ValidationError(
                    code=CFG005,
                    path=path_str,
                    field="data_sensitivity.service_categories",
                    message="invalid type for `data_sensitivity.service_categories`",
                    hint="expected a mapping of service name to category string",
                )
            )


def _validate_rule_overrides_block(
    raw: dict[str, Any],
    path_str: str,
    errors: list[ValidationError],
) -> None:
    """Validate the optional ``rule_overrides`` mapping in razin.yaml."""
    if "rule_overrides" not in raw:
        return

    overrides = raw["rule_overrides"]
    if overrides is None:
        return
    if not isinstance(overrides, dict):
        errors.append(
            ValidationError(
                code=CFG009,
                path=path_str,
                field="rule_overrides",
                message="`rule_overrides` must be a mapping",
            )
        )
        return

    for rule_id, override in overrides.items():
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(
                ValidationError(
                    code=CFG005,
                    path=path_str,
                    field="rule_overrides",
                    message="rule_overrides keys must be non-empty strings",
                )
            )
            continue
        if not isinstance(override, dict):
            errors.append(
                ValidationError(
                    code=CFG009,
                    path=path_str,
                    field=f"rule_overrides.{rule_id}",
                    message=f"`rule_overrides.{rule_id}` must be a mapping",
                )
            )
            continue

        for key in sorted(override):
            if key not in ALLOWED_RULE_OVERRIDE_KEYS:
                errors.append(
                    ValidationError(
                        code=CFG004,
                        path=path_str,
                        field=f"rule_overrides.{rule_id}.{key}",
                        message=f"unknown key `{key}` in `rule_overrides.{rule_id}`",
                        hint=_suggest_key(key, ALLOWED_RULE_OVERRIDE_KEYS),
                    )
                )

        max_severity = _validate_rule_override_severity(
            override=override,
            rule_id=rule_id,
            key="max_severity",
            path_str=path_str,
            errors=errors,
        )
        min_severity = _validate_rule_override_severity(
            override=override,
            rule_id=rule_id,
            key="min_severity",
            path_str=path_str,
            errors=errors,
        )

        if (
            max_severity is not None
            and min_severity is not None
            and SEVERITY_RANK[min_severity] > SEVERITY_RANK[max_severity]
        ):
            errors.append(
                ValidationError(
                    code=CFG008,
                    path=path_str,
                    field=f"rule_overrides.{rule_id}",
                    message=(
                        "contradictory rule override: "
                        f"min_severity {min_severity!r} is higher than max_severity {max_severity!r}"
                    ),
                    hint="set min_severity <= max_severity",
                )
            )


def _suggest_key(unknown: str, allowed: frozenset[str]) -> str:
    """Return a 'did you mean ...' hint for a close key match, or empty string."""
    matches = difflib.get_close_matches(unknown, sorted(allowed), n=1, cutoff=0.6)
    if matches:
        return f"did you mean `{matches[0]}`?"
    return ""


def _validate_rule_override_severity(
    *,
    override: dict[str, Any],
    rule_id: str,
    key: str,
    path_str: str,
    errors: list[ValidationError],
) -> str | None:
    """Validate max/min severity values in rule overrides."""
    if key not in override:
        return None
    severity = override[key]
    if not isinstance(severity, str) or severity not in RULE_OVERRIDE_ALLOWED_SEVERITIES:
        errors.append(
            ValidationError(
                code=CFG006,
                path=path_str,
                field=f"rule_overrides.{rule_id}.{key}",
                message=f"invalid value for `{key}`",
                hint=(f"expected one of: {', '.join(sorted(RULE_OVERRIDE_ALLOWED_SEVERITIES))}; " f"got: {severity!r}"),
            )
        )
        return None
    return severity
