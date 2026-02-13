"""Loader for YAML-defined detector rules.

Discovers YAML files in the yaml_rules directory, validates them against
the schema, and constructs YamlDetector instances.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from razin.detectors.yaml_rules.engine import YamlDetector
from razin.detectors.yaml_rules.schema import validate_yaml_rule
from razin.exceptions import ConfigError

logger = logging.getLogger(__name__)

YAML_RULES_DIR: Path = Path(__file__).parent


def load_yaml_detectors(
    rules_dir: Path | None = None,
    rule_ids: frozenset[str] | None = None,
) -> list[YamlDetector]:
    """Load and validate YAML rule files, returning YamlDetector instances.

    Args:
        rules_dir: Directory containing .yaml rule files. Defaults to the
            built-in yaml_rules directory.
        rule_ids: If provided, only load rules whose rule_id is in this set.

    Returns:
        List of validated YamlDetector instances, sorted by detector_id.
    """
    directory = rules_dir or YAML_RULES_DIR
    if not directory.is_dir():
        logger.warning("YAML rules directory not found: %s", directory)
        return []

    yaml_files = sorted(directory.glob("*.yaml"))
    if not yaml_files:
        logger.debug("No YAML rule files found in %s", directory)
        return []

    detectors: list[YamlDetector] = []
    for yaml_path in yaml_files:
        try:
            data = _load_yaml_file(yaml_path)
        except ConfigError:
            logger.warning("Skipping invalid YAML rule file: %s", yaml_path)
            continue

        if rule_ids is not None and data["rule_id"] not in rule_ids:
            logger.debug("Skipping rule %s (not in requested set)", data["rule_id"])
            continue

        try:
            validate_yaml_rule(data, str(yaml_path))
        except ConfigError as exc:
            logger.warning("Schema validation failed for %s: %s", yaml_path, exc)
            continue

        detectors.append(YamlDetector(data))
        logger.debug("Loaded YAML detector: %s (v%d)", data["rule_id"], data["version"])

    detectors.sort(key=lambda d: d.detector_id)
    return detectors


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load and parse a single YAML file with safe_load only."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"YAML rule file {path} must contain a mapping")

    return raw
