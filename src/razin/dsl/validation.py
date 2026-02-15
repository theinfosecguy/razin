"""Collect-all validation for DSL rule sources.

Returns a list of :class:`ValidationError` instances rather than raising,
so callers can report every problem in one pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from razin.constants.validation import (
    RULE001,
    RULE002,
    RULE003,
    RULE004,
    RULE005,
    RULE006,
    RULE007,
    RULE008,
    RULE009,
)
from razin.constants.dsl_schema import (
    ALLOWED_METADATA_KEYS,
    ALLOWED_PROFILE_KEYS,
    ALLOWED_TOP_KEYS,
    REQUIRED_METADATA_KEYS,
    REQUIRED_TOP_KEYS,
    VALID_CONFIDENCES,
    VALID_PROFILE_NAMES,
    VALID_SOURCES,
    VALID_STRATEGIES,
)
from razin.exceptions.validation import ValidationError


def validate_rule_sources(
    rules_dir: Path | None = None,
    rule_files: tuple[Path, ...] | None = None,
) -> list[ValidationError]:
    """Validate DSL rule sources and return all validation errors.

    When both *rules_dir* and *rule_files* are provided a single
    ``RULE009`` conflict error is returned immediately.  Bundled rules
    (no custom source) are skipped — nothing to validate externally.
    """
    errors: list[ValidationError] = []

    if rules_dir is not None and rule_files is not None:
        errors.append(
            ValidationError(
                code=RULE009,
                path="",
                field="",
                message="rules source conflict: choose either --rules-dir or --rule-file, not both",
            )
        )
        return errors

    if rule_files is not None:
        paths = _resolve_explicit_files(rule_files, errors)
    elif rules_dir is not None:
        paths = _resolve_rules_dir(rules_dir, errors)
    else:
        return errors  # bundled rules only — nothing to validate

    loaded_sources: dict[str, str] = {}  # rule_id → first source path
    for path in paths:
        _validate_single_rule(path, errors, loaded_sources)

    return errors


def _resolve_explicit_files(
    rule_files: tuple[Path, ...],
    errors: list[ValidationError],
) -> list[Path]:
    paths: list[Path] = []
    for rf in rule_files:
        resolved = rf.resolve()
        if not resolved.exists():
            errors.append(
                ValidationError(
                    code=RULE001,
                    path=str(resolved),
                    field="",
                    message=f"rule file not found: {resolved}",
                )
            )
            continue
        if resolved.suffix.lower() != ".yaml":
            errors.append(
                ValidationError(
                    code=RULE002,
                    path=str(resolved),
                    field="",
                    message=f"rule file must use .yaml extension: {resolved.name}",
                    hint="rename the file to use a .yaml extension",
                )
            )
            continue
        paths.append(resolved)
    return paths


def _resolve_rules_dir(
    rules_dir: Path,
    errors: list[ValidationError],
) -> list[Path]:
    resolved = rules_dir.resolve()
    if not resolved.exists() or not resolved.is_dir():
        errors.append(
            ValidationError(
                code=RULE001,
                path=str(resolved),
                field="",
                message=f"rules directory not found: {resolved}",
            )
        )
        return []
    return sorted(resolved.glob("*.yaml"))


def _validate_single_rule(
    path: Path,
    errors: list[ValidationError],
    loaded_sources: dict[str, str],
) -> None:
    path_str = str(path)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        errors.append(
            ValidationError(
                code=RULE001,
                path=path_str,
                field="",
                message=f"failed to read rule file: {exc}",
            )
        )
        return
    except yaml.YAMLError as exc:
        errors.append(
            ValidationError(
                code=RULE003,
                path=path_str,
                field="",
                message=f"invalid YAML: {exc}",
            )
        )
        return

    if not isinstance(raw, dict):
        errors.append(
            ValidationError(
                code=RULE004,
                path=path_str,
                field="",
                message=f"rule must be a mapping, got {type(raw).__name__}",
            )
        )
        return

    for key in sorted(set(raw.keys()) - ALLOWED_TOP_KEYS):
        errors.append(
            ValidationError(
                code=RULE005,
                path=path_str,
                field=key,
                message=f"unknown top-level key `{key}`",
            )
        )

    for key in sorted(REQUIRED_TOP_KEYS):
        if key not in raw:
            errors.append(
                ValidationError(
                    code=RULE006,
                    path=path_str,
                    field=key,
                    message=f"missing required field `{key}`",
                )
            )

    if "rule_id" in raw:
        rule_id = raw["rule_id"]
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(
                ValidationError(
                    code=RULE007,
                    path=path_str,
                    field="rule_id",
                    message="`rule_id` must be a non-empty string",
                )
            )
        else:
            prev = loaded_sources.get(rule_id)
            if prev is not None:
                errors.append(
                    ValidationError(
                        code=RULE008,
                        path=path_str,
                        field="rule_id",
                        message=f"duplicate rule_id `{rule_id}`",
                        hint=f"first defined in {prev}",
                    )
                )
            else:
                loaded_sources[rule_id] = path_str

    if "version" in raw:
        version = raw["version"]
        if not isinstance(version, int) or version != 1:
            errors.append(
                ValidationError(
                    code=RULE007,
                    path=path_str,
                    field="version",
                    message=f"`version` must be 1 (DSL v1), got {version!r}",
                )
            )

    if "metadata" in raw:
        _validate_rule_metadata(raw["metadata"], path_str, errors)

    if "scoring" in raw:
        _validate_rule_scoring(raw["scoring"], path_str, errors)

    if "match" in raw:
        _validate_rule_match(raw["match"], path_str, errors)

    if "dedupe" in raw and not isinstance(raw["dedupe"], bool):
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="dedupe",
                message="`dedupe` must be a boolean",
            )
        )

    if "profiles" in raw:
        _validate_rule_profiles(raw["profiles"], path_str, errors)


def _validate_rule_metadata(
    metadata: Any,
    path_str: str,
    errors: list[ValidationError],
) -> None:
    if not isinstance(metadata, dict):
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="metadata",
                message="`metadata` must be a mapping",
            )
        )
        return

    for key in sorted(set(metadata.keys()) - ALLOWED_METADATA_KEYS):
        errors.append(
            ValidationError(
                code=RULE005,
                path=path_str,
                field=f"metadata.{key}",
                message=f"unknown metadata key `{key}`",
            )
        )

    for key in sorted(REQUIRED_METADATA_KEYS):
        if key not in metadata:
            errors.append(
                ValidationError(
                    code=RULE006,
                    path=path_str,
                    field=f"metadata.{key}",
                    message=f"metadata missing required key `{key}`",
                )
            )

    if "confidence" in metadata and metadata["confidence"] not in VALID_CONFIDENCES:
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="metadata.confidence",
                message="invalid confidence value",
                hint=(f"expected one of: {', '.join(sorted(VALID_CONFIDENCES))}; " f"got: {metadata['confidence']!r}"),
            )
        )

    if "description" not in metadata and "description_template" not in metadata:
        errors.append(
            ValidationError(
                code=RULE006,
                path=path_str,
                field="metadata.description",
                message="metadata must have `description` or `description_template`",
            )
        )


def _validate_rule_scoring(
    scoring: Any,
    path_str: str,
    errors: list[ValidationError],
) -> None:
    if not isinstance(scoring, dict):
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="scoring",
                message="`scoring` must be a mapping",
            )
        )
        return

    if "base_score" not in scoring:
        errors.append(
            ValidationError(
                code=RULE006,
                path=path_str,
                field="scoring.base_score",
                message="scoring missing `base_score`",
            )
        )
    else:
        base = scoring["base_score"]
        if not isinstance(base, int) or not (0 <= base <= 100):
            errors.append(
                ValidationError(
                    code=RULE007,
                    path=path_str,
                    field="scoring.base_score",
                    message=f"`base_score` must be int 0-100, got {base!r}",
                )
            )


def _validate_rule_match(
    match: Any,
    path_str: str,
    errors: list[ValidationError],
) -> None:
    if not isinstance(match, dict):
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="match",
                message="`match` must be a mapping",
            )
        )
        return

    if "source" not in match:
        errors.append(
            ValidationError(
                code=RULE006,
                path=path_str,
                field="match.source",
                message="match missing `source`",
            )
        )
    elif match["source"] not in VALID_SOURCES:
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="match.source",
                message="invalid match source",
                hint=(f"expected one of: {', '.join(sorted(VALID_SOURCES))}; " f"got: {match['source']!r}"),
            )
        )

    if "strategy" not in match:
        errors.append(
            ValidationError(
                code=RULE006,
                path=path_str,
                field="match.strategy",
                message="match missing `strategy`",
            )
        )
    elif match["strategy"] not in VALID_STRATEGIES:
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="match.strategy",
                message="invalid match strategy",
                hint=(f"expected one of: {', '.join(sorted(VALID_STRATEGIES))}; " f"got: {match['strategy']!r}"),
            )
        )


def _validate_rule_profiles(
    profiles: Any,
    path_str: str,
    errors: list[ValidationError],
) -> None:
    if not isinstance(profiles, dict):
        errors.append(
            ValidationError(
                code=RULE007,
                path=path_str,
                field="profiles",
                message="`profiles` must be a mapping",
            )
        )
        return

    for name, overrides in profiles.items():
        if name not in VALID_PROFILE_NAMES:
            errors.append(
                ValidationError(
                    code=RULE007,
                    path=path_str,
                    field=f"profiles.{name}",
                    message=f"unknown profile `{name}`",
                    hint=f"expected one of: {', '.join(sorted(VALID_PROFILE_NAMES))}",
                )
            )

        if not isinstance(overrides, dict):
            errors.append(
                ValidationError(
                    code=RULE007,
                    path=path_str,
                    field=f"profiles.{name}",
                    message=f"`profiles.{name}` must be a mapping",
                )
            )
            continue

        for key in sorted(set(overrides.keys()) - ALLOWED_PROFILE_KEYS):
            errors.append(
                ValidationError(
                    code=RULE005,
                    path=path_str,
                    field=f"profiles.{name}.{key}",
                    message=f"unknown key `{key}` in profiles.{name}",
                )
            )

        if "score_override" in overrides:
            score = overrides["score_override"]
            if not isinstance(score, int) or not (0 <= score <= 100):
                errors.append(
                    ValidationError(
                        code=RULE007,
                        path=path_str,
                        field=f"profiles.{name}.score_override",
                        message=f"`score_override` must be int 0-100, got {score!r}",
                    )
                )
