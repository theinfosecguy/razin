"""Raisin package."""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("raisin")
except PackageNotFoundError:
    __version__ = "0.0.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
