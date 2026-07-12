"""Shared type aliases for Razin."""

from .cache import CacheFileEntry, CacheNamespace, CachePayload
from .common import (
    AssessmentState,
    Classification,
    Confidence,
    CoverageStatus,
    EvidenceVerdict,
    JsonObject,
    JsonScalar,
    JsonValue,
    RuleDisableSource,
    Severity,
    SignalKind,
    WorkspaceAssessment,
    WorkspaceEvidenceVerdict,
)
from .config import (
    DataSensitivityConfig,
    DetectorConfig,
    IocConfig,
    PackageAnalysisConfig,
    RuleOverrideConfig,
    ToolTierConfig,
)
from .init_config import DomainCount, InitConfigDraft, InitFromScanAnalysis

__all__ = [
    "CacheFileEntry",
    "CacheNamespace",
    "CachePayload",
    "AssessmentState",
    "Classification",
    "Confidence",
    "CoverageStatus",
    "DataSensitivityConfig",
    "DetectorConfig",
    "DomainCount",
    "EvidenceVerdict",
    "InitConfigDraft",
    "InitFromScanAnalysis",
    "IocConfig",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "RuleDisableSource",
    "RuleOverrideConfig",
    "Severity",
    "SignalKind",
    "PackageAnalysisConfig",
    "ToolTierConfig",
    "WorkspaceEvidenceVerdict",
    "WorkspaceAssessment",
]
