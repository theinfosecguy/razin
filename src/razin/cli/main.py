"""CLI entrypoint for Razin scanner."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from razin import __version__
from razin.constants.branding import CLI_DESCRIPTION
from razin.constants.reporting import VALID_OUTPUT_FORMATS
from razin.exceptions import ConfigError, RazinError
from razin.exceptions.validation import format_errors
from razin.reporting.stdout import StdoutReporter
from razin.scanner import scan_workspace
from razin.validation import preflight_validate


def build_parser() -> argparse.ArgumentParser:
    """Build top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="razin",
        description=CLI_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a workspace for risky skill patterns")
    scan.add_argument("-r", "--root", type=Path, required=True, help="Workspace root path")
    scan.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory root (no files written if omitted)",
    )
    scan.add_argument("-c", "--config", type=Path, help="Explicit config file")
    scan.add_argument(
        "-m",
        "--mcp-allowlist",
        action="append",
        default=[],
        help="Allowlisted MCP endpoint/domain (repeat flag for multiple values)",
    )
    scan.add_argument(
        "-p",
        "--profile",
        choices=["strict", "balanced", "audit"],
        default=None,
        help="Policy profile: strict (all signals), balanced (default, reduced noise), audit (informational only)",
    )
    rules_source = scan.add_mutually_exclusive_group()
    rules_source.add_argument(
        "-R",
        "--rules-dir",
        type=Path,
        default=None,
        help="Custom DSL rules directory (loads only *.yaml files from this folder)",
    )
    rules_source.add_argument(
        "-f",
        "--rule-file",
        type=Path,
        action="append",
        default=None,
        help="Custom DSL rule file path (repeat for multiple files)",
    )
    scan.add_argument("-n", "--no-cache", action="store_true", help="Disable cache reads/writes")
    scan.add_argument(
        "--rules-mode",
        choices=["replace", "overlay"],
        default="replace",
        help="Rule composition mode: replace (custom replaces bundled, default) or overlay (merge bundled + custom)",
    )
    scan.add_argument(
        "--duplicate-policy",
        choices=["error", "override"],
        default=None,
        help="Duplicate rule_id policy for overlay mode: error (fail fast, default) or override (custom wins)",
    )
    scan.add_argument("--max-file-mb", type=int, help="Skip SKILL.md files larger than this size")
    scan.add_argument(
        "--output-format",
        default="json",
        help="Comma-separated output formats: json, csv, sarif (default: json)",
    )
    scan.add_argument("--no-stdout", action="store_true", help="Silence stdout output")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan.add_argument("-v", "--verbose", action="store_true", help="Show cache stats and diagnostics")

    validate = subparsers.add_parser("validate-config", help="Validate configuration without scanning")
    validate.add_argument("-r", "--root", type=Path, required=True, help="Workspace root path")
    validate.add_argument("-c", "--config", type=Path, help="Explicit config file")
    rules_validate = validate.add_mutually_exclusive_group()
    rules_validate.add_argument(
        "-R",
        "--rules-dir",
        type=Path,
        default=None,
        help="Custom DSL rules directory",
    )
    rules_validate.add_argument(
        "-f",
        "--rule-file",
        type=Path,
        action="append",
        default=None,
        help="Custom DSL rule file path (repeat for multiple files)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command == "validate-config":
        return _handle_validate_config(args)

    if args.command != "scan":
        parser.error(f"Unsupported command: {args.command}")

    if args.duplicate_policy is not None and args.rules_mode != "overlay":
        print(
            "Configuration error: --duplicate-policy is only valid with --rules-mode overlay",
            file=sys.stderr,
        )
        return 2

    effective_duplicate_policy = args.duplicate_policy if args.duplicate_policy is not None else "error"

    raw_tokens = args.output_format.split(",")
    output_formats = tuple(fmt for fmt in (t.strip() for t in raw_tokens) if fmt)
    if not output_formats or len(output_formats) != len(raw_tokens):
        print(
            "Configuration error: --output-format contains empty or malformed tokens",
            file=sys.stderr,
        )
        return 2
    invalid_formats = set(output_formats) - VALID_OUTPUT_FORMATS
    if invalid_formats:
        print(
            f"Configuration error: unknown output format(s): {', '.join(sorted(invalid_formats))}. "
            f"Valid formats: {', '.join(sorted(VALID_OUTPUT_FORMATS))}",
            file=sys.stderr,
        )
        return 2

    validation_errors = preflight_validate(
        root=args.root,
        config_path=args.config,
        rules_dir=args.rules_dir,
        rule_files=(tuple(args.rule_file) if args.rule_file else None),
    )
    if validation_errors:
        print(format_errors(validation_errors), file=sys.stderr)
        return 2

    try:
        result = scan_workspace(
            root=args.root,
            out=args.output_dir,
            config_path=args.config,
            mcp_allowlist=tuple(args.mcp_allowlist),
            no_cache=args.no_cache,
            max_file_mb=args.max_file_mb,
            profile=args.profile,
            rules_dir=args.rules_dir,
            rule_files=(tuple(args.rule_file) if args.rule_file else None),
            rules_mode=args.rules_mode,
            duplicate_policy=effective_duplicate_policy,
            output_formats=output_formats,
        )
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except RazinError as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        return 1

    if not args.no_stdout:
        use_color = not args.no_color and sys.stdout.isatty()
        reporter = StdoutReporter(result, color=use_color, verbose=args.verbose)
        print(reporter.render())

    return 0


def _handle_validate_config(args: argparse.Namespace) -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
