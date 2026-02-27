"""Rule execution set resolution for config and CLI disable controls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from razin.constants.config import (
    RULE_DISABLE_SOURCE_CLI_DISABLE,
    RULE_DISABLE_SOURCE_CLI_ONLY,
    RULE_DISABLE_SOURCE_CONFIG,
)
from razin.exceptions import ConfigError
from razin.types import DetectorConfig, RuleDisableSource, RuleOverrideConfig


@dataclass(frozen=True)
class EffectiveRuleSelection:
    """Deterministic effective rule-selection output for a scan run."""

    executed_rule_ids: tuple[str, ...]
    disabled_rule_ids: tuple[str, ...]
    disable_sources: dict[str, RuleDisableSource]
    active_rule_overrides: dict[str, RuleOverrideConfig]
    unknown_config_rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class DetectorToggleSelection:
    """Resolved detector-toggle overlay derived from `detectors` config."""

    rule_overrides: dict[str, RuleOverrideConfig]
    unknown_enabled_rule_ids: tuple[str, ...]
    unknown_disabled_rule_ids: tuple[str, ...]


def resolve_detector_toggles(
    *,
    available_rule_ids: tuple[str, ...],
    detectors: DetectorConfig,
    rule_overrides: dict[str, RuleOverrideConfig],
) -> DetectorToggleSelection:
    """Resolve detector toggles into config-style disable overrides.

    Semantics:

    - If `detectors.enabled` is non-empty, only listed known rule IDs are
      initially selected.
    - Otherwise, all available rule IDs are initially selected.
    - `detectors.disabled` removes matching known rule IDs from the selection.
    - Any rule removed by detector toggles is forced to `enabled: false`.
    """
    available_set = set(available_rule_ids)
    enabled_set = set(detectors.enabled)
    disabled_set = set(detectors.disabled)

    unknown_enabled = tuple(sorted(enabled_set - available_set))
    unknown_disabled = tuple(sorted(disabled_set - available_set))

    if enabled_set:
        selected = {rule_id for rule_id in available_rule_ids if rule_id in enabled_set}
    else:
        selected = set(available_rule_ids)
    selected -= {rule_id for rule_id in disabled_set if rule_id in available_set}

    disabled_by_detectors = {rule_id for rule_id in available_rule_ids if rule_id not in selected}
    merged_overrides = dict(rule_overrides)
    for rule_id in sorted(disabled_by_detectors):
        existing = merged_overrides.get(rule_id)
        if existing is None:
            merged_overrides[rule_id] = RuleOverrideConfig(enabled=False)
            continue
        if existing.enabled:
            merged_overrides[rule_id] = RuleOverrideConfig(
                enabled=False,
                max_severity=existing.max_severity,
                min_severity=existing.min_severity,
            )

    return DetectorToggleSelection(
        rule_overrides=merged_overrides,
        unknown_enabled_rule_ids=unknown_enabled,
        unknown_disabled_rule_ids=unknown_disabled,
    )


def resolve_effective_rule_selection(
    *,
    loaded_rule_ids: tuple[str, ...],
    config_rule_overrides: dict[str, RuleOverrideConfig],
    cli_disable_rules: tuple[str, ...],
    cli_only_rules: tuple[str, ...],
) -> EffectiveRuleSelection:
    """Resolve effective executed/disabled rule IDs with deterministic precedence."""
    loaded_set = set(loaded_rule_ids)
    unknown_config_rule_ids = tuple(sorted(set(config_rule_overrides) - loaded_set))
    known_overrides = {
        rule_id: override for rule_id, override in sorted(config_rule_overrides.items()) if rule_id in loaded_set
    }

    cli_disable_set = set(cli_disable_rules)
    cli_only_set = set(cli_only_rules)
    _raise_unknown_cli_rules("--disable-rule", sorted(cli_disable_set - loaded_set))
    _raise_unknown_cli_rules("--only-rules", sorted(cli_only_set - loaded_set))

    config_disabled_set = {rule_id for rule_id, override in known_overrides.items() if not override.enabled}

    disable_sources: dict[str, RuleDisableSource]
    if cli_only_set:
        executed_rule_ids = tuple(rule_id for rule_id in loaded_rule_ids if rule_id in cli_only_set)
        disabled_rule_ids = tuple(rule_id for rule_id in loaded_rule_ids if rule_id not in cli_only_set)
        disable_sources = {
            rule_id: cast(RuleDisableSource, RULE_DISABLE_SOURCE_CLI_ONLY) for rule_id in disabled_rule_ids
        }
    else:
        executed_rule_ids = tuple(
            rule_id
            for rule_id in loaded_rule_ids
            if rule_id not in config_disabled_set and rule_id not in cli_disable_set
        )
        executed_set = set(executed_rule_ids)
        disabled_rule_ids = tuple(rule_id for rule_id in loaded_rule_ids if rule_id not in executed_set)
        disable_sources = {}
        for rule_id in disabled_rule_ids:
            if rule_id in config_disabled_set:
                disable_sources[rule_id] = cast(RuleDisableSource, RULE_DISABLE_SOURCE_CONFIG)
            else:
                disable_sources[rule_id] = cast(RuleDisableSource, RULE_DISABLE_SOURCE_CLI_DISABLE)

    executed_set = set(executed_rule_ids)
    active_rule_overrides = {
        rule_id: override for rule_id, override in known_overrides.items() if rule_id in executed_set
    }

    return EffectiveRuleSelection(
        executed_rule_ids=executed_rule_ids,
        disabled_rule_ids=disabled_rule_ids,
        disable_sources=disable_sources,
        active_rule_overrides=active_rule_overrides,
        unknown_config_rule_ids=unknown_config_rule_ids,
    )


def _raise_unknown_cli_rules(flag: str, unknown_rule_ids: list[str]) -> None:
    """Raise ConfigError when CLI rule selectors contain unknown rule IDs."""
    if not unknown_rule_ids:
        return
    raise ConfigError(f"Unknown rule IDs for {flag}: {', '.join(unknown_rule_ids)}")
