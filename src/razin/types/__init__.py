"""Shared type aliases for Razin."""

from .cache import CacheFileEntry, CacheNamespace, CachePayload
from .common import (
    AssessmentState,
    Classification,
    Confidence,
    JsonObject,
    JsonScalar,
    JsonValue,
    RuleDisableSource,
    Severity,
    SignalKind,
    WorkspaceAssessment,
)
from .config import DataSensitivityConfig, DetectorConfig, RuleOverrideConfig, ToolTierConfig
from .init_config import DomainCount, InitConfigDraft, InitFromScanAnalysis

__all__ = [
    "CacheFileEntry",
    "CacheNamespace",
    "CachePayload",
    "AssessmentState",
    "Classification",
    "Confidence",
    "DataSensitivityConfig",
    "DetectorConfig",
    "DomainCount",
    "InitConfigDraft",
    "InitFromScanAnalysis",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "RuleDisableSource",
    "RuleOverrideConfig",
    "Severity",
    "SignalKind",
    "ToolTierConfig",
    "WorkspaceAssessment",
]
