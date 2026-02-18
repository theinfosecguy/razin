"""Shared type aliases for Razin."""

from .cache import CacheFileEntry, CacheNamespace, CachePayload
from .common import Classification, Confidence, JsonObject, JsonScalar, JsonValue, Severity
from .config import DataSensitivityConfig, DetectorConfig, RuleOverrideConfig, ToolTierConfig
from .init_config import DomainCount, InitConfigDraft, InitFromScanAnalysis

__all__ = [
    "CacheFileEntry",
    "CacheNamespace",
    "CachePayload",
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
    "RuleOverrideConfig",
    "Severity",
    "ToolTierConfig",
]
