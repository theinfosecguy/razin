"""End-to-end scan orchestration for Razin."""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import replace
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from razin.config import RazinConfig, config_fingerprint, load_config
from razin.constants.cache import CACHE_FILENAME
from razin.constants.engines import ENGINE_DSL, REMOVED_ENGINE_CHOICES
from razin.constants.ids import FINDING_ID_HEX_LENGTH
from razin.constants.profiles import VALID_PROFILES
from razin.constants.reporting import VALID_OUTPUT_FORMATS
from razin.dsl import DslEngine
from razin.dsl.errors import DslError
from razin.exceptions import ConfigError, SkillParseError
from razin.io import file_sha256
from razin.model import Evidence, Finding, FindingCandidate, ScanResult
from razin.parsers import parse_skill_markdown_file
from razin.scanner.cache import build_scan_fingerprint, load_cache, new_cache, save_cache
from razin.scanner.discovery import derive_skill_name, discover_skill_files
from razin.scanner.mcp_remote import collect_mcp_remote_candidates, resolve_associated_mcp_json
from razin.scanner.score import aggregate_overall_score, aggregate_severity, severity_counts
from razin.types import CacheNamespace, CachePayload, Confidence, Severity

logger = logging.getLogger(__name__)


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
        config = _apply_mcp_allowlist_override(config, mcp_allowlist)
    resolved_max_file_mb = max_file_mb if max_file_mb is not None else config.max_file_mb

    warnings: list[str] = []
    resolved_engine = _resolve_engine(engine)
    resolved_rules_dir, resolved_rule_files = _resolve_rule_sources(
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

    findings_by_skill: dict[str, list[Finding]] = {}

    cache_path = (out / CACHE_FILENAME) if out is not None else None
    cache_payload = new_cache() if (no_cache or out is None) else load_cache(cache_path)  # type: ignore[arg-type]
    fingerprint = config_fingerprint(config, resolved_max_file_mb)
    scan_fingerprint = build_scan_fingerprint(
        config_fingerprint=fingerprint,
        engine=resolved_engine,
        rulepack_fingerprint=rulepack_fingerprint,
    )
    cache_namespace = _get_or_create_cache_namespace(
        cache_payload=cache_payload,
        scan_fingerprint=scan_fingerprint,
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
        mcp_dependency = _resolve_mcp_dependency_signature(path=path, root=root, warnings=warnings)

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
        if _is_cache_hit(entry, sha256=sha256, mtime_ns=mtime_ns, mcp_dependency=mcp_dependency):
            assert isinstance(entry, dict)
            cache_hits += 1
            skill_name = entry["skill_name"]
            cached_findings = _deserialize_findings(entry["findings"])
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
        candidates = _suppress_redundant_candidates(candidates)

        findings = [
            _candidate_to_finding(
                skill_name,
                candidate,
                high_severity_min=config.high_severity_min,
                medium_severity_min=config.medium_severity_min,
            )
            for candidate in candidates
        ]
        findings_by_skill[skill_name].extend(findings)

        cache_entry: dict[str, object] = {
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

    all_findings: list[Finding] = []
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
        cache_payload["namespaces"][scan_fingerprint] = cache_namespace
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


def _is_cache_hit(
    entry: object,
    *,
    sha256: str,
    mtime_ns: int,
    mcp_dependency: tuple[str, int, str] | None,
) -> bool:
    """Return True when skill file and MCP dependency signatures match cache entry."""
    if not isinstance(entry, dict):
        return False

    cached_sha256 = entry.get("sha256")
    cached_mtime_ns = entry.get("mtime_ns")
    if not isinstance(cached_sha256, str):
        return False
    if not isinstance(cached_mtime_ns, int):
        return False

    if cached_sha256 != sha256 or cached_mtime_ns != mtime_ns:
        return False

    cached_mcp_path = entry.get("mcp_json_path")
    cached_mcp_mtime_ns = entry.get("mcp_json_mtime_ns")
    cached_mcp_sha256 = entry.get("mcp_json_sha256")

    if mcp_dependency is None:
        return (
            cached_mcp_path is None
            and cached_mcp_mtime_ns is None
            and cached_mcp_sha256 is None
        )

    if not isinstance(cached_mcp_path, str):
        return False
    if not isinstance(cached_mcp_mtime_ns, int):
        return False
    if not isinstance(cached_mcp_sha256, str):
        return False

    return (cached_mcp_path, cached_mcp_mtime_ns, cached_mcp_sha256) == mcp_dependency


def _resolve_mcp_dependency_signature(
    *,
    path: Path,
    root: Path,
    warnings: list[str],
) -> tuple[str, int, str] | None:
    """Build cache signature tuple for associated `.mcp.json`, when present."""
    mcp_path = resolve_associated_mcp_json(path, root)
    if mcp_path is None:
        return None

    try:
        mcp_stat = mcp_path.stat()
        mcp_mtime_ns = int(mcp_stat.st_mtime_ns)
        mcp_sha256 = file_sha256(mcp_path)
    except OSError as exc:
        warning = f"Failed to read MCP JSON metadata: {mcp_path} ({exc})"
        warnings.append(warning)
        logger.warning(warning)
        return (str(mcp_path), -1, "")

    return (str(mcp_path), mcp_mtime_ns, mcp_sha256)


def _get_or_create_cache_namespace(
    *,
    cache_payload: CachePayload,
    scan_fingerprint: str,
    config_fingerprint: str,
    engine: str,
    rulepack_fingerprint: str,
) -> CacheNamespace:
    """Return an existing cache namespace or create a fresh one.

    The scan_fingerprint is derived from config_fingerprint, engine, and
    rulepack_fingerprint so a matching key guarantees all components match.
    """
    namespaces = cache_payload["namespaces"]
    namespace = namespaces.get(scan_fingerprint)
    if namespace is not None:
        return {
            "scan_fingerprint": scan_fingerprint,
            "config_fingerprint": config_fingerprint,
            "engine": engine,
            "rulepack_fingerprint": rulepack_fingerprint,
            "files": namespace["files"],
        }

    return _new_namespace(
        scan_fingerprint=scan_fingerprint,
        config_fingerprint=config_fingerprint,
        engine=engine,
        rulepack_fingerprint=rulepack_fingerprint,
    )


def _new_namespace(
    *,
    scan_fingerprint: str,
    config_fingerprint: str,
    engine: str,
    rulepack_fingerprint: str,
) -> CacheNamespace:
    """Create an empty cache namespace payload."""
    return {
        "scan_fingerprint": scan_fingerprint,
        "config_fingerprint": config_fingerprint,
        "engine": engine,
        "rulepack_fingerprint": rulepack_fingerprint,
        "files": {},
    }


def _candidate_to_finding(
    skill_name: str,
    candidate: FindingCandidate,
    *,
    high_severity_min: int = 70,
    medium_severity_min: int = 40,
) -> Finding:
    """Convert a finding candidate into a stable, serialized finding."""
    score = max(0, min(100, int(candidate.score)))
    severity = aggregate_severity(score, high_min=high_severity_min, medium_min=medium_severity_min)

    identity = "|".join(
        [
            skill_name,
            candidate.rule_id,
            candidate.title,
            candidate.description,
            candidate.evidence.path,
            str(candidate.evidence.line),
            candidate.evidence.snippet,
        ]
    )
    finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:FINDING_ID_HEX_LENGTH]

    return Finding(
        id=finding_id,
        severity=severity,
        score=score,
        confidence=candidate.confidence,
        title=candidate.title,
        description=candidate.description,
        evidence=candidate.evidence,
        skill=skill_name,
        rule_id=candidate.rule_id,
        recommendation=candidate.recommendation,
    )


def _suppress_redundant_candidates(candidates: list[FindingCandidate]) -> list[FindingCandidate]:
    """Suppress lower-value findings already covered by stronger MCP evidence."""
    mcp_evidence = {
        (candidate.evidence.path, candidate.evidence.line)
        for candidate in candidates
        if candidate.rule_id == "MCP_ENDPOINT"
    }
    if not mcp_evidence:
        return candidates

    kept: list[FindingCandidate] = []
    for candidate in candidates:
        evidence_key = (candidate.evidence.path, candidate.evidence.line)
        if candidate.rule_id == "NET_UNKNOWN_DOMAIN" and evidence_key in mcp_evidence:
            continue
        kept.append(candidate)

    return kept


def _deserialize_findings(payload: object) -> list[Finding]:
    """Deserialize cached finding payload dictionaries into Finding models."""
    if not isinstance(payload, list):
        logger.debug("Cache entry findings is not a list, skipping")
        return []

    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            logger.debug("Skipping malformed cache finding entry: %s", type(item).__name__)
            continue

        evidence_payload = item.get("evidence", {})
        if not isinstance(evidence_payload, dict):
            evidence_payload = {}

        findings.append(
            Finding(
                id=str(item.get("id", "")),
                severity=_as_severity(item.get("severity")),
                score=int(item.get("score", 0)),
                confidence=_as_confidence(item.get("confidence")),
                title=str(item.get("title", "")),
                description=str(item.get("description", "")),
                evidence=Evidence(
                    path=str(evidence_payload.get("path", "")),
                    line=(int(evidence_payload["line"]) if evidence_payload.get("line") is not None else None),
                    snippet=str(evidence_payload.get("snippet", "")),
                ),
                skill=str(item.get("skill", "")),
                rule_id=str(item.get("rule_id", "")),
                recommendation=str(item.get("recommendation", "")),
            )
        )

    return findings


def _as_severity(value: object) -> Severity:
    """Coerce an arbitrary value into a valid severity enum."""
    if isinstance(value, str) and value in {"low", "medium", "high"}:
        return cast(Severity, value)
    return "low"


def _as_confidence(value: object) -> Confidence:
    """Coerce an arbitrary value into a valid confidence enum."""
    if isinstance(value, str) and value in {"low", "medium", "high"}:
        return cast(Confidence, value)
    return "low"


def _apply_mcp_allowlist_override(
    config: RazinConfig,
    mcp_allowlist: tuple[str, ...],
) -> RazinConfig:
    """Return a config with CLI-provided MCP allowlist values normalized."""
    domains: list[str] = []
    for item in mcp_allowlist:
        normalized = _normalize_domain_or_url(item)
        if normalized:
            domains.append(normalized)

    unique_sorted = tuple(sorted(set(domains)))
    return replace(config, mcp_allowlist_domains=unique_sorted)


def _normalize_domain_or_url(value: str) -> str | None:
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


def _resolve_engine(engine: str) -> str:
    """Validate and normalize the selected scan engine value."""
    normalized = engine.strip().lower()

    if normalized == ENGINE_DSL:
        return ENGINE_DSL

    removed = ", ".join(REMOVED_ENGINE_CHOICES)
    raise ConfigError(
        f"Unsupported engine '{engine}'. Razin now supports only '{ENGINE_DSL}'. "
        f"Removed values: {removed}. Use '--engine dsl' or omit '--engine'."
    )


def _resolve_rule_sources(
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
