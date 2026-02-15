"""Configuration loading, validation, and normalization for Razin scans.

This package facade re-exports all public names so that existing
``from razin.config import ...`` statements continue to work.
"""

from __future__ import annotations

from razin.config.fingerprint import config_fingerprint, effective_detector_ids
from razin.config.loader import load_config
from razin.config.model import RazinConfig
from razin.config.validator import _suggest_key, validate_config_file

__all__ = [
    "RazinConfig",
    "_suggest_key",
    "config_fingerprint",
    "effective_detector_ids",
    "load_config",
    "validate_config_file",
]
