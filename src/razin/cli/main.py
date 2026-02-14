"""CLI entrypoint for Raisin scanner."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from razin import __version__
from razin.constants.branding import ASCII_LOGO_LINES, BRAND_NAME
from razin.exceptions import ConfigError, RaisinError
from razin.reporting.stdout import StdoutReporter
from razin.scanner import scan_workspace

CLI_DESCRIPTION: str = "\n".join((*ASCII_LOGO_LINES, "", f"{BRAND_NAME} skill scanner"))


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
        choices=["json"],
        default="json",
        help="Output artifact format (default: json)",
    )
    scan.add_argument("--no-stdout", action="store_true", help="Silence stdout output")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan.add_argument("-v", "--verbose", action="store_true", help="Show cache stats and diagnostics")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command != "scan":
        parser.error(f"Unsupported command: {args.command}")

    if args.duplicate_policy is not None and args.rules_mode != "overlay":
        print(
            "Configuration error: --duplicate-policy is only valid with --rules-mode overlay",
            file=sys.stderr,
        )
        return 2

    effective_duplicate_policy = args.duplicate_policy if args.duplicate_policy is not None else "error"

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
        )
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except RaisinError as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        return 1

    if not args.no_stdout:
        use_color = not args.no_color and sys.stdout.isatty()
        reporter = StdoutReporter(result, color=use_color, verbose=args.verbose)
        print(reporter.render())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
