"""Deterministic DSL runtime engine.

Loads YAML rule files, compiles them into execution plans, and runs them
against parsed skill documents to produce FindingCandidate outputs.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import yaml

from razin.config import RazinConfig
from razin.dsl.compiler import CompiledRule, compile_rule
from razin.dsl.context import EvalContext
from razin.dsl.errors import DslCompileError, DslRuntimeError, DslSchemaError
from razin.dsl.ops import OP_REGISTRY
from razin.exceptions import ConfigError
from razin.model import FindingCandidate, ParsedSkillDocument

logger = logging.getLogger(__name__)

RULES_DIR: Path = Path(__file__).parent / "rules"


class DslEngine:
    """Option C declarative rule engine.

    Loads and compiles YAML rules at construction time, then executes them
    deterministically against parsed skill documents.
    """

    def __init__(
        self,
        rules_dir: Path | None = None,
        rule_files: tuple[Path, ...] | None = None,
        rule_ids: frozenset[str] | None = None,
        rules_mode: str = "replace",
        duplicate_policy: str = "error",
    ) -> None:
        self._rules_dir = rules_dir
        self._rule_files = rule_files
        self._rules_mode = rules_mode
        self._duplicate_policy = duplicate_policy
        self._compiled: list[CompiledRule] = []
        self._raw_rules: list[dict[str, Any]] = []
        self._load(rule_ids)

    def _load(self, rule_ids: frozenset[str] | None) -> None:
        """Load and compile all YAML rule files from the selected source."""
        yaml_files = self._collect_rule_paths()
        bundled_paths = self._bundled_path_set()
        loaded_rule_sources: dict[str, Path] = {}

        for yaml_path in yaml_files:
            raw = self._load_rule(yaml_path)

            internal_rule_id = raw.get("rule_id")
            public_rule_id = raw.get("public_rule_id", internal_rule_id)

            if rule_ids is not None and internal_rule_id not in rule_ids and public_rule_id not in rule_ids:
                continue

            try:
                compiled = compile_rule(raw, str(yaml_path))
            except (DslCompileError, DslSchemaError) as exc:
                raise ConfigError(str(exc)) from exc

            previous_source = loaded_rule_sources.get(compiled.rule_id)
            if previous_source is not None:
                is_bundled_vs_custom = (
                    previous_source in bundled_paths and yaml_path not in bundled_paths
                )
                if (
                    self._rules_mode == "overlay"
                    and self._duplicate_policy == "override"
                    and is_bundled_vs_custom
                ):
                    self._override_rule(compiled, raw, previous_source, yaml_path)
                    loaded_rule_sources[compiled.rule_id] = yaml_path
                    continue
                raise ConfigError(
                    f"Duplicate rule_id '{compiled.rule_id}' loaded from {previous_source} and {yaml_path}. "
                    f"To let the custom rule win, use --duplicate-policy override."
                )
            loaded_rule_sources[compiled.rule_id] = yaml_path

            self._compiled.append(compiled)
            self._raw_rules.append(raw)
            logger.debug("Loaded DSL rule: %s v%d", compiled.rule_id, compiled.version)

        self._compiled.sort(key=lambda r: (r.rule_id, r.public_rule_id, r.source_path))

    def _bundled_path_set(self) -> frozenset[Path]:
        """Return resolved paths of bundled rules for source attribution."""
        bundled_dir = RULES_DIR.resolve()
        if not bundled_dir.exists() or not bundled_dir.is_dir():
            return frozenset()
        return frozenset(path.resolve() for path in bundled_dir.glob("*.yaml"))

    def _override_rule(
        self,
        compiled: CompiledRule,
        raw: dict[str, Any],
        previous_source: Path,
        new_source: Path,
    ) -> None:
        """Replace a previously loaded rule with the new one (custom wins)."""
        new_compiled: list[CompiledRule] = []
        new_raw: list[dict[str, Any]] = []
        for existing_rule, existing_raw in zip(self._compiled, self._raw_rules, strict=True):
            if existing_rule.rule_id != compiled.rule_id:
                new_compiled.append(existing_rule)
                new_raw.append(existing_raw)
        new_compiled.append(compiled)
        new_raw.append(raw)
        self._compiled = new_compiled
        self._raw_rules = new_raw
        logger.info(
            "Override: rule '%s' from %s replaced by %s",
            compiled.rule_id,
            previous_source,
            new_source,
        )

    @staticmethod
    def _load_rule(path: Path) -> dict[str, Any]:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"Failed to read rule file {path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ConfigError(f"Rule file {path} must contain a mapping")
        return raw

    def _collect_rule_paths(self) -> tuple[Path, ...]:
        if self._rules_dir is not None and self._rule_files is not None:
            raise ConfigError("Rules source conflict: choose either rules_dir or rule_files, not both.")

        has_custom = self._rules_dir is not None or self._rule_files is not None

        if has_custom and self._rules_mode == "overlay":
            return self._collect_overlay_paths()

        if self._rule_files is not None:
            return self._collect_explicit_rule_files(self._rule_files)

        selected_dir = self._rules_dir if self._rules_dir is not None else RULES_DIR
        rules_dir = selected_dir.resolve()
        if not rules_dir.exists():
            raise ConfigError(f"Rules directory does not exist: {rules_dir}")
        if not rules_dir.is_dir():
            raise ConfigError(f"Rules directory is not a directory: {rules_dir}")

        return tuple(sorted(path.resolve() for path in rules_dir.glob("*.yaml")))

    def _collect_overlay_paths(self) -> tuple[Path, ...]:
        """Collect bundled paths first, then custom paths for overlay merging."""
        bundled_dir = RULES_DIR.resolve()
        if not bundled_dir.exists() or not bundled_dir.is_dir():
            raise ConfigError(f"Bundled rules directory missing: {bundled_dir}")

        bundled = tuple(sorted(path.resolve() for path in bundled_dir.glob("*.yaml")))

        if self._rule_files is not None:
            custom = self._collect_explicit_rule_files(self._rule_files)
        else:
            assert self._rules_dir is not None
            custom_dir = self._rules_dir.resolve()
            if not custom_dir.exists():
                raise ConfigError(f"Rules directory does not exist: {custom_dir}")
            if not custom_dir.is_dir():
                raise ConfigError(f"Rules directory is not a directory: {custom_dir}")
            custom = tuple(sorted(path.resolve() for path in custom_dir.glob("*.yaml")))

        return bundled + custom

    @staticmethod
    def _collect_explicit_rule_files(rule_files: tuple[Path, ...]) -> tuple[Path, ...]:
        if len(rule_files) == 0:
            raise ConfigError("At least one --rule-file path must be provided.")

        resolved_files: list[Path] = []
        seen_paths: set[Path] = set()
        for rule_file in rule_files:
            resolved = rule_file.resolve()
            if resolved in seen_paths:
                raise ConfigError(f"Duplicate rule file path provided: {resolved}")
            seen_paths.add(resolved)

            if not resolved.exists():
                raise ConfigError(f"Rule file does not exist: {resolved}")
            if not resolved.is_file():
                raise ConfigError(f"Rule file path is not a file: {resolved}")
            if resolved.suffix.lower() != ".yaml":
                raise ConfigError(f"Rule file must use .yaml extension: {resolved}")

            resolved_files.append(resolved)

        return tuple(sorted(resolved_files))

    @property
    def rule_ids(self) -> list[str]:
        """Return sorted list of loaded rule IDs."""
        return [r.rule_id for r in self._compiled]

    @property
    def public_rule_ids(self) -> list[str]:
        """Return public compatibility rule IDs in load order."""
        return [r.public_rule_id for r in self._compiled]

    @property
    def rule_id_map(self) -> dict[str, str]:
        """Return internal->public rule identifier mapping."""
        return {rule.rule_id: rule.public_rule_id for rule in self._compiled}

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return len(self._compiled)

    def run_all(
        self,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        """Execute all compiled rules against a parsed skill document."""
        ctx = EvalContext(skill_name=skill_name, parsed=parsed, config=config)
        all_findings: list[FindingCandidate] = []

        for rule in self._compiled:
            findings = self._execute_rule(rule, ctx)
            all_findings.extend(findings)

        return all_findings

    def run_rule(
        self,
        rule_id: str,
        *,
        skill_name: str,
        parsed: ParsedSkillDocument,
        config: RazinConfig,
    ) -> list[FindingCandidate]:
        """Execute a single rule by ID."""
        ctx = EvalContext(skill_name=skill_name, parsed=parsed, config=config)
        for rule in self._compiled:
            if rule.rule_id == rule_id:
                return self._execute_rule(rule, ctx)

        public_matches = [rule for rule in self._compiled if rule.public_rule_id == rule_id]
        if len(public_matches) == 1:
            return self._execute_rule(public_matches[0], ctx)
        if len(public_matches) > 1:
            raise DslRuntimeError(
                f"Rule '{rule_id}' maps to multiple internal rules; use internal rule_id for single-rule execution"
            )
        raise DslRuntimeError(f"Rule '{rule_id}' not loaded")

    def _execute_rule(
        self,
        rule: CompiledRule,
        ctx: EvalContext,
    ) -> list[FindingCandidate]:
        """Execute a single compiled rule and stamp rule_id on results."""
        strategy_fn = OP_REGISTRY.get(rule.strategy_name)
        if strategy_fn is None:
            raise DslRuntimeError(f"Strategy '{rule.strategy_name}' not in op registry")

        base_score = self._resolve_score(rule, ctx)

        candidates = strategy_fn(
            ctx,
            rule.match_config,
            rule.metadata,
            base_score,
            rule.dedupe,
        )

        stamped: list[FindingCandidate] = []
        for candidate in candidates:
            stamped.append(
                FindingCandidate(
                    rule_id=rule.public_rule_id,
                    score=candidate.score,
                    confidence=candidate.confidence,
                    title=candidate.title,
                    description=candidate.description,
                    evidence=candidate.evidence,
                    recommendation=candidate.recommendation,
                    internal_rule_id=rule.rule_id,
                )
            )
        return stamped

    def fingerprint(self) -> str:
        """Return a stable hash of all loaded rules for cache invalidation."""
        payload = [
            {
                "rule_id": r.rule_id,
                "public_rule_id": r.public_rule_id,
                "source_path": r.source_path,
                "version": r.version,
                "strategy": r.strategy_name,
                "match": r.match_config,
                "metadata": r.metadata,
                "base_score": r.base_score,
                "dedupe": r.dedupe,
                "profiles": r.profiles,
            }
            for r in self._compiled
        ]
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    @staticmethod
    def _resolve_score(rule: CompiledRule, ctx: EvalContext) -> int:
        """Resolve base_score with profile overlay if applicable."""
        profile = ctx.config.profile
        if profile and rule.profiles:
            overlay = rule.profiles.get(profile)
            if overlay and "score_override" in overlay:
                return int(overlay["score_override"])
        return rule.base_score
