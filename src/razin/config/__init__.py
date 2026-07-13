"""Configuration loading, validation, and normalization for Razin scans.

Public API for the config package.
"""

from __future__ import annotations

from razin.config.fingerprint import config_fingerprint, effective_detector_ids, package_analysis_fingerprint
from razin.config.loader import load_config
from razin.config.model import RazinConfig
from razin.config.validator import _suggest_key, validate_config_file

__all__ = [
    "RazinConfig",
    "_suggest_key",
    "config_fingerprint",
    "effective_detector_ids",
    "load_config",
    "package_analysis_fingerprint",
    "validate_config_file",
]
