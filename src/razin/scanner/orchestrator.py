"""End-to-end scan orchestration for Razin.

The ``scan_workspace`` function remains here as the primary entry point.
Internal helpers have been extracted to ``razin.scanner.pipeline.*`` submodules
and are re-exported here with underscore prefixes for backward compatibility.
"""

from __future__ import annotations

import logging
import time
from dataclasses import replace
from pathlib import Path

from razin.config import config_fingerprint, load_config
from razin.constants.cache import CACHE_FILENAME
from razin.constants.engines import ENGINE_DSL
from razin.constants.profiles import VALID_PROFILES
from razin.constants.reporting import VALID_OUTPUT_FORMATS
from razin.dsl import DslEngine
from razin.dsl.errors import DslError
from razin.exceptions import ConfigError, SkillParseError
from razin.io import file_sha256
from razin.model import ScanResult
from razin.parsers import parse_skill_markdown_file
from razin.scanner.cache import build_scan_fingerprint, load_cache, new_cache, save_cache
from razin.scanner.discovery import derive_skill_name, discover_skill_files
from razin.scanner.mcp_remote import collect_mcp_remote_candidates
from razin.scanner.pipeline.cache_utils import (
    get_or_create_cache_namespace,
    is_cache_hit,
    resolve_mcp_dependency_signature,
)
from razin.scanner.pipeline.config_resolution import (
    apply_mcp_allowlist_override,
    normalize_domain_or_url,
    resolve_engine,
    resolve_rule_sources,
)
from razin.scanner.pipeline.conversion import (
    candidate_to_finding,
    deserialize_findings,
    suppress_redundant_candidates,
)
from razin.scanner.score import aggregate_overall_score, aggregate_severity, severity_counts
from razin.types import CacheFileEntry

logger = logging.getLogger(__name__)

_is_cache_hit = is_cache_hit
_resolve_mcp_dependency_signature = resolve_mcp_dependency_signature
_get_or_create_cache_namespace = get_or_create_cache_namespace
_candidate_to_finding = candidate_to_finding
_suppress_redundant_candidates = suppress_redundant_candidates
_deserialize_findings = deserialize_findings
_apply_mcp_allowlist_override = apply_mcp_allowlist_override
_normalize_domain_or_url = normalize_domain_or_url
_resolve_engine = resolve_engine
_resolve_rule_sources = resolve_rule_sources


def scan_workspace(
    *,
    root: Path,
    out: Path | None = None,
    config_path: Path | None = None,
    mcp_allowlist: tuple[str, ...] | None = None,
    no_cache: bool = False,
    max_file_mb: int | None = None,
    profile: str | None = None,
    engine: str = ENGINE_DSL,
    rules_dir: Path | None = None,
    rule_files: tuple[Path, ...] | None = None,
    rules_mode: str = "replace",
    duplicate_policy: str = "error",
    output_formats: tuple[str, ...] = ("json",),
) -> ScanResult:
    """Scan a workspace and optionally write per-skill findings and summaries."""
    invalid_formats = set(output_formats) - VALID_OUTPUT_FORMATS
    if invalid_formats:
        raise ConfigError(
            f"Unknown output format(s): {', '.join(sorted(invalid_formats))}. "
            f"Valid formats: {', '.join(sorted(VALID_OUTPUT_FORMATS))}"
        )

    started_at = time.perf_counter()
    root = root.resolve()
    if out is not None:
        out = out.resolve()

    if not root.is_dir():
        raise ConfigError(f"Scan root does not exist or is not a directory: {root}")

    config = load_config(root, config_path)
    if profile is not None and profile in VALID_PROFILES:
        config = replace(config, profile=profile)  # type: ignore[arg-type]
    if mcp_allowlist:
        config = apply_mcp_allowlist_override(config, mcp_allowlist)
    resolved_max_file_mb = max_file_mb if max_file_mb is not None else config.max_file_mb

    warnings: list[str] = []
    resolved_engine = resolve_engine(engine)
    resolved_rules_dir, resolved_rule_files = resolve_rule_sources(
        rules_dir=rules_dir,
        rule_files=rule_files,
    )

    skill_files = discover_skill_files(root, config.skill_globs, resolved_max_file_mb)

    try:
        dsl_engine = DslEngine(
            rule_ids=None,
            rules_dir=resolved_rules_dir,
            rule_files=resolved_rule_files,
            rules_mode=rules_mode,
            duplicate_policy=duplicate_policy,
        )
    except DslError as exc:
        raise ConfigError(str(exc)) from exc
    rulepack_fingerprint = dsl_engine.fingerprint()

    findings_by_skill: dict[str, list] = {}

    cache_path = (out / CACHE_FILENAME) if out is not None else None
    cache_payload = new_cache() if (no_cache or out is None) else load_cache(cache_path)  # type: ignore[arg-type]
    fingerprint = config_fingerprint(config, resolved_max_file_mb)
    scan_fp = build_scan_fingerprint(
        config_fingerprint=fingerprint,
        engine=resolved_engine,
        rulepack_fingerprint=rulepack_fingerprint,
    )
    cache_namespace = get_or_create_cache_namespace(
        cache_payload=cache_payload,
        scan_fingerprint=scan_fp,
        config_fingerprint=fingerprint,
        engine=resolved_engine,
        rulepack_fingerprint=rulepack_fingerprint,
    )
    cache_files = cache_namespace["files"]
    cache_hits = 0
    cache_misses = 0
    discovered_keys: set[str] = set()

    for path in skill_files:
        cache_key = str(path)
        discovered_keys.add(cache_key)
        mcp_dependency = resolve_mcp_dependency_signature(path=path, root=root, warnings=warnings)

        try:
            stat = path.stat()
            mtime_ns = int(stat.st_mtime_ns)
            sha256 = file_sha256(path)
        except OSError as exc:
            warning = f"Failed to read file metadata: {path} ({exc})"
            warnings.append(warning)
            logger.warning(warning)
            continue

        entry = cache_files.get(cache_key)
        if is_cache_hit(entry, sha256=sha256, mtime_ns=mtime_ns, mcp_dependency=mcp_dependency):
            assert isinstance(entry, dict)
            cache_hits += 1
            skill_name = entry["skill_name"]
            cached_findings = deserialize_findings(entry["findings"])
            findings_by_skill.setdefault(skill_name, []).extend(cached_findings)
            continue

        cache_misses += 1
        try:
            parsed = parse_skill_markdown_file(path)
        except SkillParseError as exc:
            warning = f"Parse error in {path}: {exc}"
            warnings.append(warning)
            logger.warning(warning)
            cache_files.pop(cache_key, None)
            continue

        declared_name = None
        if isinstance(parsed.frontmatter, dict):
            name_value = parsed.frontmatter.get("name")
            if isinstance(name_value, str) and name_value.strip():
                declared_name = name_value.strip()

        skill_name = derive_skill_name(path, root, declared_name=declared_name)
        findings_by_skill.setdefault(skill_name, [])

        candidates = dsl_engine.run_all(skill_name=skill_name, parsed=parsed, config=config)
        mcp_candidates, mcp_warnings = collect_mcp_remote_candidates(
            parsed=parsed,
            root=root,
            config=config,
        )
        candidates.extend(mcp_candidates)
        for warning in mcp_warnings:
            warnings.append(warning)
            logger.warning(warning)
        candidates = suppress_redundant_candidates(candidates)

        findings = [
            candidate_to_finding(
                skill_name,
                candidate,
                high_severity_min=config.high_severity_min,
                medium_severity_min=config.medium_severity_min,
            )
            for candidate in candidates
        ]
        findings_by_skill[skill_name].extend(findings)

        cache_entry: CacheFileEntry = {
            "mtime_ns": mtime_ns,
            "sha256": sha256,
            "skill_name": skill_name,
            "findings": [finding.to_dict() for finding in findings],
        }
        if mcp_dependency is not None:
            cache_entry["mcp_json_path"] = mcp_dependency[0]
            cache_entry["mcp_json_mtime_ns"] = mcp_dependency[1]
            cache_entry["mcp_json_sha256"] = mcp_dependency[2]
        cache_files[cache_key] = cache_entry

    for stale_key in set(cache_files) - discovered_keys:
        cache_files.pop(stale_key, None)

    all_findings = []
    min_rule_score = config.aggregate_min_rule_score
    high_sev_min = config.high_severity_min
    medium_sev_min = config.medium_severity_min
    for skill_name in sorted(findings_by_skill):
        skill_findings = findings_by_skill[skill_name]
        if out is not None:
            from razin.reporting.writer import write_skill_reports

            write_skill_reports(
                out,
                skill_name,
                skill_findings,
                min_rule_score=min_rule_score,
                high_severity_min=high_sev_min,
                medium_severity_min=medium_sev_min,
            )
        all_findings.extend(skill_findings)

    if out is not None:
        if "csv" in output_formats:
            from razin.reporting.csv_writer import write_csv_findings

            write_csv_findings(out, all_findings)

        if "sarif" in output_formats:
            from razin.reporting.sarif_writer import write_sarif_findings

            write_sarif_findings(out, all_findings)

    if not no_cache and out is not None and cache_path is not None:
        cache_namespace["files"] = cache_files
        cache_payload["namespaces"][scan_fp] = cache_namespace
        save_cache(cache_path, cache_payload)

    duration_seconds = time.perf_counter() - started_at
    counts = severity_counts(all_findings)
    agg_score = aggregate_overall_score(
        all_findings,
        min_rule_score=config.aggregate_min_rule_score,
    )
    agg_severity = aggregate_severity(
        agg_score,
        high_min=config.high_severity_min,
        medium_min=config.medium_severity_min,
    )

    sorted_findings = sorted(all_findings, key=lambda f: (-f.score, f.id))

    return ScanResult(
        scanned_files=len(skill_files),
        total_findings=len(all_findings),
        aggregate_score=agg_score,
        aggregate_severity=agg_severity,
        counts_by_severity=counts,
        findings=tuple(sorted_findings),
        duration_seconds=duration_seconds,
        warnings=tuple(warnings),
        cache_hits=cache_hits,
        cache_misses=cache_misses,
    )
