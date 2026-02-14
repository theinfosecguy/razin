"""Detector package for Razin."""

from .base import Detector
from .rules import build_detectors

__all__ = ["Detector", "build_detectors"]
