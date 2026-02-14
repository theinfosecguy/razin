"""Preflight validation orchestrator.

Combines config-file and DSL-rule-source validation into a single
entry point that both ``razin validate-config`` and ``razin scan``
share, keeping the two paths in sync.
"""

from __future__ import annotations

from pathlib import Path

from razin.config import validate_config_file
from razin.constants.validation import CFG010
from razin.dsl.validation import validate_rule_sources
from razin.exceptions.validation import ValidationError, sort_errors


def preflight_validate(
    root: Path,
    config_path: Path | None = None,
    *,
    rules_dir: Path | None = None,
    rule_files: tuple[Path, ...] | None = None,
) -> list[ValidationError]:
    """Run all preflight validation checks and return errors in deterministic order.

    Returns an empty list when everything is valid.
    """
    errors: list[ValidationError] = []
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        errors.append(
            ValidationError(
                code=CFG010,
                path=str(resolved_root),
                field="",
                message=f"root directory does not exist: {resolved_root}",
            )
        )
        return sort_errors(errors)

    config_explicit = config_path is not None
    errors.extend(validate_config_file(root, config_path, config_explicit=config_explicit))
    errors.extend(validate_rule_sources(rules_dir=rules_dir, rule_files=rule_files))
    return sort_errors(errors)
