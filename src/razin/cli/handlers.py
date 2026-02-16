"""CLI subcommand handlers and threshold evaluation."""

from __future__ import annotations

import argparse
import sys

from razin.constants.scoring import SEVERITY_RANK
from razin.exceptions.validation import format_errors
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
