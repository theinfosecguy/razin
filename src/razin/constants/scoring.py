"""Constants for score-to-severity mapping and ranking."""

from __future__ import annotations

HIGH_SEVERITY_MIN_SCORE: int = 70
MEDIUM_SEVERITY_MIN_SCORE: int = 40
TOP_RISKS_DEFAULT_LIMIT: int = 5

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# Only rules with per-rule max score >= this threshold contribute to the
# probabilistic-OR aggregate.  Rules below this are treated as context
# signals and excluded from the aggregate to prevent saturation from many
# low-confidence informational findings.
AGGREGATE_MIN_RULE_SCORE: int = 40
