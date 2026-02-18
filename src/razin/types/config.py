"""Typed configuration structures for Razin scanner settings."""

from __future__ import annotations

from dataclasses import dataclass

from razin.constants.data_sensitivity import (
    HIGH_SENSITIVITY_KEYWORDS,
    HIGH_SENSITIVITY_SERVICES,
    LOW_SENSITIVITY_SERVICES,
    MEDIUM_SENSITIVITY_KEYWORDS,
    MEDIUM_SENSITIVITY_SERVICES,
)
from razin.constants.docs import (
    TOOL_TIER_DESTRUCTIVE_KEYWORDS,
    TOOL_TIER_WRITE_KEYWORDS,
)
from razin.types.common import Severity


@dataclass(frozen=True)
class ToolTierConfig:
    """Keyword tiers for tool token risk classification."""

    destructive: tuple[str, ...] = TOOL_TIER_DESTRUCTIVE_KEYWORDS
    write: tuple[str, ...] = TOOL_TIER_WRITE_KEYWORDS


@dataclass(frozen=True)
class DataSensitivityConfig:
    """Configurable service registry and keywords for data sensitivity classification."""

    high_services: tuple[str, ...] = HIGH_SENSITIVITY_SERVICES
    medium_services: tuple[str, ...] = MEDIUM_SENSITIVITY_SERVICES
    low_services: tuple[str, ...] = LOW_SENSITIVITY_SERVICES
    high_keywords: tuple[str, ...] = HIGH_SENSITIVITY_KEYWORDS
    medium_keywords: tuple[str, ...] = MEDIUM_SENSITIVITY_KEYWORDS
    service_categories: dict[str, str] | None = None


@dataclass(frozen=True)
class DetectorConfig:
    """Detector enablement toggles."""

    enabled: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleOverrideConfig:
    """Per-rule override settings from ``razin.yaml``."""

    max_severity: Severity | None = None
    min_severity: Severity | None = None
