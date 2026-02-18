"""Shared type aliases for Razin."""

from .cache import CacheFileEntry, CacheNamespace, CachePayload
from .common import Confidence, JsonObject, JsonScalar, JsonValue, Severity
from .config import DataSensitivityConfig, DetectorConfig, ToolTierConfig
from .init_config import DomainCount, InitConfigDraft, InitFromScanAnalysis

__all__ = [
    "CacheFileEntry",
    "CacheNamespace",
    "CachePayload",
    "Confidence",
    "DataSensitivityConfig",
    "DetectorConfig",
    "DomainCount",
    "InitConfigDraft",
    "InitFromScanAnalysis",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "Severity",
    "ToolTierConfig",
]
