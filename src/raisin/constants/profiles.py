"""Policy profile constants and presets.

Raisin supports three policy profiles that control scoring thresholds
and aggregate behavior without changing which detectors run:

- ``strict``: All findings contribute to aggregate; no domain suppression
  beyond explicit allowlists.  Suitable for high-assurance review.
- ``balanced``: Context-only signals (TOOL_INVOCATION, DYNAMIC_SCHEMA,
  MCP_REQUIRED, EXTERNAL_URLS) are excluded from aggregate scoring.
  Local/dev hosts are always suppressed.  Suitable for team triage.
- ``audit``: All findings are reported but aggregate score is always 0
  (informational-only).  Suitable for exploration and labeling.
"""

from __future__ import annotations

from typing import Literal

ProfileName = Literal["strict", "balanced", "audit"]

VALID_PROFILES: frozenset[str] = frozenset({"strict", "balanced", "audit"})
DEFAULT_PROFILE: ProfileName = "balanced"

# Per-profile minimum rule score for aggregate contribution.
# Rules with a per-rule max below this threshold are excluded from
# the probabilistic-OR aggregate (they still appear as findings).
PROFILE_AGGREGATE_MIN_SCORE: dict[str, int] = {
    "strict": 20,
    "balanced": 40,
    "audit": 101,  # nothing contributes → aggregate falls back to max
}

# Per-profile severity thresholds.  Balanced raises the bar so that
# single common signals (e.g. MCP_ENDPOINT at 70) don't push every
# skill to high — reviewers see high only for genuinely multi-signal risk.
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
