"""CLI registration and lazy dispatch for sandbox verification."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from typing import Any


def register_sandbox_parser(subparsers: Any) -> None:
    """Register isolated two-phase sandbox commands without importing runtime code."""
    sandbox = subparsers.add_parser(
        "sandbox",
        help="Seal and simulate an explicitly approved sandbox verification plan",
    )
    commands = sandbox.add_subparsers(dest="sandbox_command", required=True)

    plan = commands.add_parser("plan", help="Create a sealed bundle and approval-bound plan; execute nothing")
    plan.add_argument("-r", "--root", type=Path, required=True, help="Skill package root containing SKILL.md")
    plan.add_argument("-o", "--plan-out", type=Path, required=True, help="Plan JSON path outside the skill root")
    plan.add_argument(
        "--backend",
        choices=["simulated"],
        required=True,
        help="Explicit backend (v1 supports only non-executing 'simulated')",
    )
    plan.add_argument(
        "--image",
        required=True,
        help="Immutable intended image reference: name@sha256:<64 lowercase hex>",
    )
    plan.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        metavar="-- COMMAND [ARG ...]",
        help="Exact intended argv after --; it is recorded but not executed by v1",
    )

    run = commands.add_parser("run", help="Verify an approved plan and bundle, then simulate the backend call")
    run.add_argument("--plan", type=Path, required=True, help="Existing plan JSON path")
    run.add_argument(
        "--approve-plan-sha256",
        required=True,
        help="Exact approval binding printed by 'sandbox plan'",
    )
    run.add_argument("-o", "--result-out", type=Path, required=True, help="Simulation result JSON path")


def _normalized_remainder(argv: list[str]) -> list[str]:
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def handle_sandbox(args: argparse.Namespace) -> int:
    """Lazily execute sandbox handlers so ordinary scans remain disconnected."""
    from razin.exceptions import SandboxBackendError, SandboxValidationError
    from razin.sandbox.service import create_plan, run_plan

    try:
        if args.sandbox_command == "plan":
            plan = create_plan(
                root=args.root,
                plan_path=args.plan_out,
                argv=_normalized_remainder(args.argv),
                backend=args.backend,
                image_reference=args.image,
            )
            approval = plan["approval"]["binding_sha256"]
            bundle = plan["bundle"]
            run_command = shlex.join(
                [
                    "razin",
                    "sandbox",
                    "run",
                    "--plan",
                    str(args.plan_out),
                    "--approve-plan-sha256",
                    approval,
                    "--result-out",
                    str(args.plan_out.with_name("sandbox-result.json")),
                ]
            )
            print(f"Plan: {args.plan_out}")
            print(f"Bundle SHA-256: {bundle['sha256']}")
            print(f"Approval SHA-256: {approval}")
            print(f"Run simulation: {run_command}")
            print("No code was executed.")
            return 0
        if args.sandbox_command == "run":
            result = run_plan(
                plan_path=args.plan,
                approval_sha256=args.approve_plan_sha256,
                result_path=args.result_out,
            )
            print(f"Result: {args.result_out}")
            print(f"Execution status: {result['execution_status']}")
            print("No code was executed; this result is not dynamic evidence or a safety verdict.")
            return 0
    except SandboxValidationError as exc:
        print(f"Sandbox validation error: {exc}", file=sys.stderr)
        return 2
    except SandboxBackendError as exc:
        print(f"Sandbox backend error: {exc}", file=sys.stderr)
        return 1
    raise AssertionError(f"unsupported sandbox command: {args.sandbox_command}")
