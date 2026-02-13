"""Constants for name normalization and sanitization."""

from __future__ import annotations

import re
from re import Pattern

NON_ALNUM_DASH_PATTERN: Pattern[str] = re.compile(r"[^a-z0-9]+")
NON_OUTPUT_NAME_PATTERN: Pattern[str] = re.compile(r"[^a-z0-9._-]+")
COLLAPSE_DASH_PATTERN: Pattern[str] = re.compile(r"-+")
