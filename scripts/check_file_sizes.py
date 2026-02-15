#!/usr/bin/env python3
"""Guardrail script that enforces file-size caps on source and test modules.

Soft-cap violations produce warnings; hard-cap violations cause a non-zero exit.

Caps (lines of code, excluding blank lines and comments):
    Source (src/razin/**/*.py): soft 400, hard 700
    Tests  (tests/**/*.py):    soft 500, hard 900
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC_SOFT_CAP: int = 400
SRC_HARD_CAP: int = 700
TEST_SOFT_CAP: int = 500
TEST_HARD_CAP: int = 900

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
SRC_DIR: Path = REPO_ROOT / "src" / "razin"
TEST_DIR: Path = REPO_ROOT / "tests"


def _count_loc(path: Path) -> int:
    """Count lines of code excluding blank lines and comment-only lines."""
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def _check_directory(
    directory: Path,
    soft_cap: int,
    hard_cap: int,
    label: str,
) -> tuple[list[str], list[str]]:
    """Check all .py files under *directory* against the given caps.

    Returns (warnings, errors) lists.
    """
    warnings: list[str] = []
    errors: list[str] = []

    for py_file in sorted(directory.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue
        loc = _count_loc(py_file)
        rel = py_file.relative_to(REPO_ROOT)
        if loc > hard_cap:
            errors.append(f"HARD-CAP  {label} {rel}: {loc} LOC (cap {hard_cap})")
        elif loc > soft_cap:
            warnings.append(f"SOFT-CAP  {label} {rel}: {loc} LOC (cap {soft_cap})")

    return warnings, errors


def main() -> int:
    """Run file-size guardrail checks and return exit code."""
    all_warnings: list[str] = []
    all_errors: list[str] = []

    for directory, soft, hard, label in [
        (SRC_DIR, SRC_SOFT_CAP, SRC_HARD_CAP, "src"),
        (TEST_DIR, TEST_SOFT_CAP, TEST_HARD_CAP, "test"),
    ]:
        if not directory.exists():
            continue
        warns, errs = _check_directory(directory, soft, hard, label)
        all_warnings.extend(warns)
        all_errors.extend(errs)

    for w in all_warnings:
        print(f"WARNING: {w}")
    for e in all_errors:
        print(f"ERROR:   {e}")

    if all_errors:
        print(f"\n{len(all_errors)} hard-cap violation(s) found.")
        return 1

    if all_warnings:
        print(f"\n{len(all_warnings)} soft-cap warning(s) (no hard-cap violations).")

    if not all_warnings and not all_errors:
        print("All files within size caps.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
