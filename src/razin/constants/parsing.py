"""Constants for parsing behavior."""

from __future__ import annotations

import re
from re import Pattern

SNIPPET_MAX_LENGTH: int = 200
FRONTMATTER_DELIMITER: str = "---"
# YAML allows "..." as an explicit document end marker.
FRONTMATTER_ALT_DELIMITER: str = "..."

KEY_LINE_PATTERN: Pattern[str] = re.compile(r"^\s*([A-Za-z0-9_-]{2,})\s*:")
KEY_LINE_EXCLUDE: frozenset[str] = frozenset({"http", "https"})
