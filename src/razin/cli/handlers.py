"""CLI subcommand handlers and threshold evaluation."""

from __future__ import annotations

import argparse
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

from razin.cli.init_flow import (
    build_unified_diff,
    collect_init_config,
    default_init_config,
    prompt_yes_no,
    render_init_yaml,
)
from razin.config import validate_config_file
from razin.constants.config import CONFIG_FILENAME
from razin.constants.init import INIT_CONFIG_TEMP_PREFIX, INIT_CONFIG_TEMP_SUFFIX
from razin.constants.scoring import SEVERITY_RANK
from razin.exceptions.validation import ValidationError, format_errors
from razin.io.json_io import write_text_atomic
from razin.model import ScanResult
from razin.validation import preflight_validate


def evaluate_fail_thresholds(
    result: ScanResult,
    *,
    fail_on: str | None,
    fail_on_score: int | None,
) -> int:
    """Return 1 if result exceeds CI thresholds, 0 otherwise.

    When both ``--fail-on`` and ``--fail-on-score`` are provided, either
    condition being met causes failure (logical OR).
    """
    if fail_on is not None:
        threshold = SEVERITY_RANK.get(fail_on, 0)
        for finding in result.findings:
            if SEVERITY_RANK.get(finding.severity, 0) >= threshold:
                return 1

    if fail_on_score is not None and result.aggregate_score >= fail_on_score:
        return 1

    return 0


def handle_validate_config(args: argparse.Namespace) -> int:
    """Run config + rule validation and report results."""
    errors = preflight_validate(
        root=args.root,
        config_path=args.config,
        rules_dir=args.rules_dir,
        rule_files=(tuple(args.rule_file) if args.rule_file else None),
    )
    if errors:
        print(format_errors(errors), file=sys.stderr)
        return 2

    print("Configuration is valid.")
    return 0


def handle_init(args: argparse.Namespace) -> int:
    """Run ``razin init`` interactive/bootstrap flow."""
    root = args.root.resolve()
    if not root.is_dir():
        print(f"Configuration error: root directory does not exist: {root}", file=sys.stderr)
        return 2

    target_path = args.config.resolve() if args.config is not None else (root / CONFIG_FILENAME)

    try:
        draft = default_init_config() if args.yes else collect_init_config(read=input, write=print)
    except (EOFError, KeyboardInterrupt):
        print("Init cancelled.", file=sys.stderr)
        return 130

    rendered = render_init_yaml(draft)
    validation_errors = _validate_generated_config(root=root, rendered=rendered)
    if validation_errors:
        print(format_errors(validation_errors), file=sys.stderr)
        return 2

    existing_content = target_path.read_text(encoding="utf-8") if target_path.exists() else None
    if existing_content is not None:
        print(build_unified_diff(existing_content, rendered, target_path))

    if args.dry_run:
        print(f"# Dry run: no file written. Target: {target_path}")
        print(rendered, end="")
        return 0

    if not args.yes:
        if existing_content is not None:
            overwrite = prompt_yes_no(
                "Overwrite existing configuration file?",
                default=False,
                read=input,
                write=print,
            )
            if not overwrite:
                print("Skipped writing configuration.")
                return 0
        else:
            write_new = prompt_yes_no(
                f"Write configuration to {target_path}?",
                default=True,
                read=input,
                write=print,
            )
            if not write_new:
                print("Skipped writing configuration.")
                return 0

    write_text_atomic(
        path=target_path,
        content=rendered,
        temp_prefix=INIT_CONFIG_TEMP_PREFIX,
        temp_suffix=INIT_CONFIG_TEMP_SUFFIX,
    )
    print(f"Wrote config to {target_path}")
    return 0


def _validate_generated_config(*, root: Path, rendered: str) -> list[ValidationError]:
    """Validate generated YAML before writing it to disk."""
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=root,
            prefix=INIT_CONFIG_TEMP_PREFIX,
            suffix=INIT_CONFIG_TEMP_SUFFIX,
            delete=False,
        ) as handle:
            handle.write(rendered)
            temp_path = Path(handle.name)
        return validate_config_file(root, temp_path, config_explicit=True)
    finally:
        if temp_path is not None:
            with suppress(FileNotFoundError):
                temp_path.unlink()
