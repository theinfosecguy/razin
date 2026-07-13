"""CLI tests for explicit sandbox planning and simulation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from razin.cli.main import build_parser, main

IMAGE = "example.invalid/razin@sha256:" + "a" * 64


def _skill(path: Path) -> Path:
    path.mkdir()
    (path / "SKILL.md").write_text("---\nname: cli-fixture\n---\n", encoding="utf-8")
    return path


def test_parser_accepts_nested_sandbox_commands(tmp_path: Path) -> None:
    parser = build_parser()
    plan = parser.parse_args(
        [
            "sandbox",
            "plan",
            "-r",
            str(tmp_path),
            "-o",
            "plan.json",
            "--backend",
            "simulated",
            "--image",
            IMAGE,
            "--",
            "python3",
            "helper.py",
        ]
    )
    run = parser.parse_args(
        ["sandbox", "run", "--plan", "plan.json", "--approve-plan-sha256", "a" * 64, "-o", "result.json"]
    )

    assert plan.command == "sandbox"
    assert plan.sandbox_command == "plan"
    assert plan.argv == ["--", "python3", "helper.py"]
    assert run.sandbox_command == "run"


def test_cli_plan_and_run_never_enter_scanner(tmp_path: Path, capsys: object) -> None:
    root = _skill(tmp_path / "skill")
    plan_path = tmp_path / "audit" / "plan.json"
    result_path = tmp_path / "result.json"

    with patch("razin.cli.main.scan_workspace", side_effect=AssertionError("scanner must not run")):
        assert (
            main(
                [
                    "sandbox",
                    "plan",
                    "-r",
                    str(root),
                    "-o",
                    str(plan_path),
                    "--backend",
                    "simulated",
                    "--image",
                    IMAGE,
                    "--",
                    "touch",
                    str(tmp_path / "sentinel"),
                ]
            )
            == 0
        )
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        assert (
            main(
                [
                    "sandbox",
                    "run",
                    "--plan",
                    str(plan_path),
                    "--approve-plan-sha256",
                    plan["approval"]["binding_sha256"],
                    "-o",
                    str(result_path),
                ]
            )
            == 0
        )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "No code was executed" in captured.out
    assert "not dynamic evidence or a safety verdict" in captured.out
    assert not (tmp_path / "sentinel").exists()


def test_cli_returns_two_for_invalid_approval(tmp_path: Path, capsys: object) -> None:
    root = _skill(tmp_path / "skill")
    plan_path = tmp_path / "audit" / "plan.json"
    assert (
        main(
            [
                "sandbox",
                "plan",
                "-r",
                str(root),
                "-o",
                str(plan_path),
                "--backend",
                "simulated",
                "--image",
                IMAGE,
                "--",
                "true",
            ]
        )
        == 0
    )

    code = main(
        [
            "sandbox",
            "run",
            "--plan",
            str(plan_path),
            "--approve-plan-sha256",
            "f" * 64,
            "-o",
            str(tmp_path / "result.json"),
        ]
    )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert code == 2
    assert "approval digest does not match" in captured.err
