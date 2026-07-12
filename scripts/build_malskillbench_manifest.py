#!/usr/bin/env python3
"""Build a package manifest from a pinned MalSkillBench checkout.

This script only enumerates package directories and filenames. It never imports
or executes corpus content.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "2.0"
SOURCE_REPOSITORY = "https://github.com/lxyeternal/MalSkillBench"
FAMILY_PATTERN = re.compile(r"__(CI|PI|MIXED)_B\d+(?:__|$)")
PINNED_INVENTORIES: dict[str, tuple[int, int]] = {
    "06e083125d5ec5dd7a189dfedadfe587a70635b9": (3944, 4000),
}


def _packages(root: Path, split: str) -> list[Path]:
    split_root = root / split
    if not split_root.is_dir():
        raise ValueError(f"Missing MalSkillBench split: {split_root}")
    return sorted(
        (path for path in split_root.iterdir() if path.is_dir() and (path / "SKILL.md").is_file()),
        key=lambda path: path.name,
    )


def build_manifest(skills_root: Path, *, commit: str) -> dict[str, Any]:
    """Return a deterministic Razin manifest for a MalSkillBench checkout."""
    skills_root = skills_root.resolve()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full 40-character lowercase Git SHA")
    samples: list[dict[str, str]] = []
    for package in _packages(skills_root, "malware"):
        match = FAMILY_PATTERN.search(package.name)
        diagnostic_group = f"filename-{match.group(1).lower()}" if match else None
        samples.append(
            {
                "id": f"malware/{package.name}",
                "path": (package / "SKILL.md").relative_to(skills_root).as_posix(),
                "label": "malicious",
                "family": "unlabeled",
                **({"diagnostic_group": diagnostic_group} if diagnostic_group else {}),
            }
        )
    for package in _packages(skills_root, "benign"):
        samples.append(
            {
                "id": f"benign/{package.name}",
                "path": (package / "SKILL.md").relative_to(skills_root).as_posix(),
                "label": "benign",
                "family": "benign-control",
            }
        )
    if not samples:
        raise ValueError("No benchmark packages found")
    malicious_count = sum(sample["label"] == "malicious" for sample in samples)
    benign_count = sum(sample["label"] == "benign" for sample in samples)
    expected_inventory = PINNED_INVENTORIES.get(commit)
    if expected_inventory is not None and (malicious_count, benign_count) != expected_inventory:
        raise ValueError(
            "Pinned inventory mismatch: "
            f"expected malicious={expected_inventory[0]} benign={expected_inventory[1]}, "
            f"observed malicious={malicious_count} benign={benign_count}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "name": f"MalSkillBench@{commit[:12]}",
        "corpus_root": skills_root.as_posix(),
        "allow_unlisted_skills": False,
        "source": {
            "repository": SOURCE_REPOSITORY,
            "commit": commit,
            "license": "academic-research-only",
        },
        "inventory": {"malicious": malicious_count, "benign": benign_count},
        "diagnostic_groups": "filename taxonomy hints only; unlabeled samples have no released family mapping",
        "scanner": {"profile": "balanced", "max_file_mb": 64},
        "samples": samples,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a manifest from a pinned MalSkillBench checkout")
    parser.add_argument("--skills-root", required=True, type=Path, help="Path to Dataset/Skills")
    parser.add_argument("--commit", required=True, help="Pinned 40-character upstream commit")
    parser.add_argument("--output", required=True, type=Path, help="Manifest output path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        manifest = build_manifest(args.skills_root, commit=args.commit)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"Manifest error: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
