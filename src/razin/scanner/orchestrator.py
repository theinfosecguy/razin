"""End-to-end scan orchestration for Razin.

The ``scan_workspace`` function remains here as the primary entry point.
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
from razin.exceptions import ConfigError, SkillParseError
from razin.exceptions.dsl import DslError
from razin.io import file_sha256
from razin.model import ScanResult
from razin.parsers import parse_skill_markdown_file
from razin.reporting.filters import OutputFilters, build_filter_metadata, filter_findings
from razin.scanner.cache import build_scan_fingerprint, load_cache, new_cache, save_cache
from razin.scanner.discovery import assign_unique_skill_names, collect_all_skill_names, discover_skill_files
from razin.scanner.mcp_remote import collect_mcp_remote_candidates
from razin.scanner.pipeline.cache_utils import (
    get_or_create_cache_namespace,
    is_cache_hit,
    resolve_mcp_dependency_signature,
)
from razin.scanner.pipeline.config_resolution import (
    apply_mcp_allowlist_override,
    resolve_engine,
    resolve_rule_sources,
)
from razin.scanner.pipeline.conversion import (
    candidate_to_finding,
    deserialize_findings,
    suppress_redundant_candidates,
)
from razin.scanner.score import aggregate_overall_score, aggregate_severity, rule_counts, severity_counts
from razin.types import CacheFileEntry, RuleOverrideConfig, Severity

logger = logging.getLogger(__name__)


def _path_for_warning(path: Path, root: Path) -> str:
    """Render a warning-friendly path relative to the scan root when possible."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


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
    min_severity: Severity | None = None,
    security_only: bool = False,
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

    if out is not None:
        try:
            out.mkdir(parents=True, exist_ok=True)
            _probe = out / ".razin_write_probe"
            _probe.touch()
            _probe.unlink()
        except (PermissionError, OSError) as exc:
            raise ConfigError(f"Output directory is not writable: {out} ({exc})") from exc

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

    if not config.typosquat_baseline and len(skill_files) >= 2:
        auto_baseline = collect_all_skill_names(skill_files, root)
        config = replace(config, typosquat_baseline=auto_baseline)
        logger.info(
            "Auto-derived typosquat baseline with %d names from %d skills",
            len(auto_baseline),
            len(skill_files),
        )
    skill_names_by_file, duplicate_name_groups = assign_unique_skill_names(skill_files, root)
    for base_name, paths in sorted(duplicate_name_groups.items()):
        rendered_paths = ", ".join(_path_for_warning(path, root) for path in paths)
        warning = (
            f"Duplicate skill name '{base_name}' resolved across multiple files "
            f"({rendered_paths}); applying deterministic suffixes."
        )
        warnings.append(warning)
        logger.warning(warning)

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
    loaded_rule_ids = set(dsl_engine.public_rule_ids)
    active_rule_overrides = {
        rule_id: override for rule_id, override in config.rule_overrides.items() if rule_id in loaded_rule_ids
    }
    unknown_rule_overrides = sorted(set(config.rule_overrides) - loaded_rule_ids)
    for rule_id in unknown_rule_overrides:
        warning = f"Unknown rule_overrides entry '{rule_id}' has no loaded rule and will be ignored."
        warnings.append(warning)
        logger.warning(warning)
    serialized_rule_overrides = _serialize_rule_overrides(active_rule_overrides)

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
        skill_name = skill_names_by_file[path]
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
        if (
            is_cache_hit(entry, sha256=sha256, mtime_ns=mtime_ns, mcp_dependency=mcp_dependency)
            and isinstance(entry, dict)
            and entry.get("skill_name") == skill_name
        ):
            assert isinstance(entry, dict)
            cache_hits += 1
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
                rule_override=active_rule_overrides.get(candidate.rule_id),
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
    output_filters = OutputFilters(min_severity=min_severity, security_only=security_only)
    min_rule_score = config.aggregate_min_rule_score
    high_sev_min = config.high_severity_min
    medium_sev_min = config.medium_severity_min
    for skill_name in sorted(findings_by_skill):
        skill_findings = findings_by_skill[skill_name]
        shown_skill_findings = filter_findings(skill_findings, output_filters)
        if out is not None:
            from razin.reporting.writer import write_skill_reports

            write_skill_reports(
                out,
                skill_name,
                shown_skill_findings,
                all_findings=skill_findings,
                min_rule_score=min_rule_score,
                high_severity_min=high_sev_min,
                medium_severity_min=medium_sev_min,
                output_filter=build_filter_metadata(
                    total=len(skill_findings),
                    shown=len(shown_skill_findings),
                    filters=output_filters,
                ),
                rule_overrides=serialized_rule_overrides,
            )
        all_findings.extend(skill_findings)

    if out is not None:
        shown_all_findings = filter_findings(all_findings, output_filters)
        filter_metadata = build_filter_metadata(
            total=len(all_findings),
            shown=len(shown_all_findings),
            filters=output_filters,
        )
        if "csv" in output_formats:
            from razin.reporting.csv_writer import write_csv_findings

            write_csv_findings(out, shown_all_findings)

        if "sarif" in output_formats:
            from razin.reporting.sarif_writer import write_sarif_findings

            write_sarif_findings(
                out,
                shown_all_findings,
                rule_distribution=rule_counts(all_findings),
                filter_metadata=filter_metadata,
                rule_overrides=serialized_rule_overrides,
            )

    if not no_cache and out is not None and cache_path is not None:
        cache_namespace["files"] = cache_files
        cache_payload["namespaces"][scan_fp] = cache_namespace
        save_cache(cache_path, cache_payload)

    duration_seconds = time.perf_counter() - started_at
    counts = severity_counts(all_findings)
    counts_by_rule = rule_counts(all_findings)
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
        high_severity_min=config.high_severity_min,
        medium_severity_min=config.medium_severity_min,
        aggregate_min_rule_score=config.aggregate_min_rule_score,
        counts_by_rule=counts_by_rule,
        active_rule_overrides={rule_id: override for rule_id, override in sorted(serialized_rule_overrides.items())},
    )


def _serialize_rule_overrides(
    active_rule_overrides: dict[str, RuleOverrideConfig],
) -> dict[str, dict[str, Severity]]:
    """Render active rule overrides for report metadata."""
    serialized: dict[str, dict[str, Severity]] = {}
    for rule_id, override in sorted(active_rule_overrides.items()):
        values: dict[str, Severity] = {}
        max_severity = getattr(override, "max_severity", None)
        min_severity = getattr(override, "min_severity", None)
        if max_severity is not None:
            values["max_severity"] = max_severity
        if min_severity is not None:
            values["min_severity"] = min_severity
        if values:
            serialized[rule_id] = values
    return serialized
