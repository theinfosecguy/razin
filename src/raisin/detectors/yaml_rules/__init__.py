"""YAML rule package for declarative detector definitions."""

from __future__ import annotations

from .engine import YamlDetector
from .loader import load_yaml_detectors

__all__ = ["YamlDetector", "load_yaml_detectors"]
