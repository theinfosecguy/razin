"""Integration tests for the full detector set against fixture data."""

from __future__ import annotations

import json
from pathlib import Path

from razin.config import effective_detector_ids, load_config
from razin.detectors import build_detectors
from razin.parsers import parse_skill_markdown_file
from razin.scanner.discovery import derive_skill_name


def test_risky_fixture_triggers_expected_rule_ids(
    fixtures_root: Path,
    basic_repo_root: Path,
) -> None:
    """Risky skill fixture triggers exactly the expected rule IDs."""
    expected_rules_path = fixtures_root / "expected" / "risky_rules.json"
    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"

    config = load_config(basic_repo_root)
    detectors = build_detectors(effective_detector_ids(config))
    parsed = parse_skill_markdown_file(risky_file)
    skill_name = derive_skill_name(risky_file, basic_repo_root)

    candidates = []
    for detector in detectors:
        candidates.extend(detector.run(skill_name=skill_name, parsed=parsed, config=config))

    observed = sorted({candidate.rule_id for candidate in candidates})
    expected = sorted(json.loads(expected_rules_path.read_text(encoding="utf-8")))

    assert observed == expected


def test_benign_file_triggers_no_findings(basic_repo_root: Path) -> None:
    """Benign skill fixture triggers no findings."""
    benign_file = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    detectors = build_detectors(effective_detector_ids(config))
    parsed = parse_skill_markdown_file(benign_file)
    skill_name = derive_skill_name(benign_file, basic_repo_root)

    candidates = []
    for detector in detectors:
        candidates.extend(detector.run(skill_name=skill_name, parsed=parsed, config=config))

    assert candidates == []
