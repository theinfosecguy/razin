"""Policy profile constants and presets.

Razin supports three policy profiles that control severity thresholds and
domain suppression without changing which detectors run:

- ``strict``: No domain suppression beyond explicit allowlists. Suitable for
  high-assurance review.
- ``balanced``: Local/dev hosts are suppressed and common signals use higher
  severity thresholds.
  Local/dev hosts are always suppressed.  Suitable for team triage.
- ``audit``: All findings are reported. Suitable for exploration and labeling.
"""

from __future__ import annotations

from typing import Literal

ProfileName = Literal["strict", "balanced", "audit"]

VALID_PROFILES: frozenset[str] = frozenset({"strict", "balanced", "audit"})
DEFAULT_PROFILE: ProfileName = "balanced"

# Deprecated compatibility values. Review priority ignores aggregate minimums.
PROFILE_AGGREGATE_MIN_SCORE: dict[str, int] = {
    "strict": 20,
    "balanced": 40,
    "audit": 101,
}

# Per-profile severity thresholds. Signal-kind policy separately prevents
# capability/review/analysis-gap rules from reaching unsupported severities.
PROFILE_HIGH_SEVERITY_MIN: dict[str, int] = {
    "strict": 70,
    "balanced": 80,
    "audit": 70,
}
PROFILE_MEDIUM_SEVERITY_MIN: dict[str, int] = {
    "strict": 40,
    "balanced": 50,
    "audit": 40,
}

# Per-profile: whether to suppress local/dev hosts in NET_UNKNOWN_DOMAIN.
PROFILE_SUPPRESS_LOCAL_HOSTS: dict[str, bool] = {
    "strict": False,
    "balanced": True,
    "audit": True,
}
