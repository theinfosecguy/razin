"""Constants for score-to-severity mapping and ranking."""

from __future__ import annotations

HIGH_SEVERITY_MIN_SCORE: int = 70
MEDIUM_SEVERITY_MIN_SCORE: int = 40
TOP_RISKS_DEFAULT_LIMIT: int = 5

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# Deprecated compatibility default. Review priority no longer combines rules
# or filters them through an aggregate threshold.
AGGREGATE_MIN_RULE_SCORE: int = 40
