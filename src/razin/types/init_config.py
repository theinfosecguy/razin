"""Type definitions for ``razin init`` configuration drafting."""

from __future__ import annotations

from dataclasses import dataclass

from razin.constants.config import DEFAULT_MAX_FILE_MB
from razin.constants.init import INIT_DEFAULT_PROFILE
from razin.constants.profiles import ProfileName


@dataclass(frozen=True)
class InitConfigDraft:
    """Collected values used to render a starter ``razin.yaml``."""

    profile: ProfileName = INIT_DEFAULT_PROFILE
    allowlist_domains: tuple[str, ...] = ()
    mcp_allowlist_domains: tuple[str, ...] = ()
    denylist_domains: tuple[str, ...] = ()
    mcp_denylist_domains: tuple[str, ...] = ()
    strict_subdomains: bool = False
    ignore_default_allowlist: bool = False
    max_file_mb: int = DEFAULT_MAX_FILE_MB
