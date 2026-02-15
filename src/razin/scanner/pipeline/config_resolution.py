"""Config resolution helpers for the scanner pipeline."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

from razin.config import RazinConfig
from razin.constants.engines import ENGINE_DSL, REMOVED_ENGINE_CHOICES
from razin.exceptions import ConfigError


def apply_mcp_allowlist_override(
    config: RazinConfig,
    mcp_allowlist: tuple[str, ...],
) -> RazinConfig:
    """Return a config with CLI-provided MCP allowlist values normalized."""
    domains: list[str] = []
    for item in mcp_allowlist:
        normalized = normalize_domain_or_url(item)
        if normalized:
            domains.append(normalized)

    unique_sorted = tuple(sorted(set(domains)))
    return replace(config, mcp_allowlist_domains=unique_sorted)


def normalize_domain_or_url(value: str) -> str | None:
    """Normalize a domain or URL into lowercase domain text."""
    stripped = value.strip().lower()
    if not stripped:
        return None

    parsed = urlparse(stripped)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname.lower().strip()

    if "://" in stripped:
        return None

    return stripped.strip("/")


def resolve_engine(engine: str) -> str:
    """Validate and normalize the selected scan engine value."""
    normalized = engine.strip().lower()

    if normalized == ENGINE_DSL:
        return ENGINE_DSL

    removed = ", ".join(REMOVED_ENGINE_CHOICES)
    raise ConfigError(
        f"Unsupported engine '{engine}'. Razin now supports only '{ENGINE_DSL}'. "
        f"Removed values: {removed}. Use '--engine dsl' or omit '--engine'."
    )


def resolve_rule_sources(
    *,
    rules_dir: Path | None,
    rule_files: tuple[Path, ...] | None,
) -> tuple[Path | None, tuple[Path, ...] | None]:
    """Resolve and validate custom rule source paths for current run."""
    has_rules_dir = rules_dir is not None
    has_rule_files = bool(rule_files)
    if has_rules_dir and has_rule_files:
        raise ConfigError("Rules source conflict: use either --rules-dir or --rule-file, not both.")

    if rules_dir is not None:
        resolved_dir = rules_dir.resolve()
        if not resolved_dir.exists():
            raise ConfigError(f"Rules directory does not exist: {resolved_dir}")
        if not resolved_dir.is_dir():
            raise ConfigError(f"Rules directory is not a directory: {resolved_dir}")
        return resolved_dir, None

    if rule_files:
        resolved_files: list[Path] = []
        seen_paths: set[Path] = set()
        for rule_file in rule_files:
            resolved_file = rule_file.resolve()
            if resolved_file in seen_paths:
                raise ConfigError(f"Duplicate rule file path provided: {resolved_file}")
            seen_paths.add(resolved_file)

            if not resolved_file.exists():
                raise ConfigError(f"Rule file does not exist: {resolved_file}")
            if not resolved_file.is_file():
                raise ConfigError(f"Rule file path is not a file: {resolved_file}")
            if resolved_file.suffix.lower() != ".yaml":
                raise ConfigError(f"Rule file must use .yaml extension: {resolved_file}")

            resolved_files.append(resolved_file)
        return None, tuple(sorted(resolved_files))

    return None, None
