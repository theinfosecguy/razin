"""End-to-end check for executable bytecode hidden behind a decoy source file."""

import json
import py_compile
import subprocess
import sys
from pathlib import Path

from razin.cli.main import main


def test_bytecode_substitution_requires_complete_coverage_gate(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: bytecode-check\ndescription: Harmless bytecode check\n---\n\nUse helper.py.\n",
        encoding="utf-8",
    )
    (skill / "helper.py").write_text('VALUE = "source"\n', encoding="utf-8")
    alternate = tmp_path / "alternate.py"
    alternate.write_text('VALUE = "bytecode"\n', encoding="utf-8")
    cache = skill / "__pycache__" / f"helper.{sys.implementation.cache_tag}.pyc"
    cache.parent.mkdir()
    py_compile.compile(
        str(alternate),
        cfile=str(cache),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )

    imported = subprocess.check_output(
        [sys.executable, "-c", "import helper; print(helper.VALUE)"], cwd=skill, text=True
    )
    assert imported.strip() == "bytecode"

    reports = tmp_path / "reports"
    args = ["scan", "-r", str(skill), "-o", str(reports), "--fail-on", "medium", "--no-stdout"]
    assert main(args) == 0
    summary = json.loads(next(reports.rglob("summary.json")).read_text(encoding="utf-8"))
    assert summary["coverage_status"] == "incomplete"
    assert f"python-bytecode:__pycache__/{cache.name}" in summary["coverage_reasons"]
    assert main([*args, "--require-complete-coverage"]) == 1
