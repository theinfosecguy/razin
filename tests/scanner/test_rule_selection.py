"""Tests for effective rule selection precedence and validation."""

from __future__ import annotations

import pytest

from razin.exceptions import ConfigError
from razin.scanner.pipeline.rule_selection import resolve_effective_rule_selection
from razin.types import RuleOverrideConfig


def test_config_disabled_rule_is_excluded_from_execution() -> None:
    """Config `enabled: false` removes a rule from the executed set."""
    selection = resolve_effective_rule_selection(
        loaded_rule_ids=("A", "B", "C"),
        config_rule_overrides={"B": RuleOverrideConfig(enabled=False)},
        cli_disable_rules=(),
        cli_only_rules=(),
    )

    assert selection.executed_rule_ids == ("A", "C")
    assert selection.disabled_rule_ids == ("B",)
    assert selection.disable_sources == {"B": "config"}


def test_cli_disable_rule_excludes_rule_for_current_run() -> None:
    """CLI `--disable-rule` removes a rule from the executed set."""
    selection = resolve_effective_rule_selection(
        loaded_rule_ids=("A", "B", "C"),
        config_rule_overrides={},
        cli_disable_rules=("C",),
        cli_only_rules=(),
    )

    assert selection.executed_rule_ids == ("A", "B")
    assert selection.disabled_rule_ids == ("C",)
    assert selection.disable_sources == {"C": "cli-disable"}


def test_cli_only_rules_wins_over_config_and_disable_rule() -> None:
    """`--only-rules` has highest precedence in effective-rule selection."""
    selection = resolve_effective_rule_selection(
        loaded_rule_ids=("A", "B", "C"),
        config_rule_overrides={"B": RuleOverrideConfig(enabled=False)},
        cli_disable_rules=("A",),
        cli_only_rules=("B",),
    )

    assert selection.executed_rule_ids == ("B",)
    assert selection.disabled_rule_ids == ("A", "C")
    assert selection.disable_sources == {"A": "cli-only", "C": "cli-only"}


def test_unknown_cli_disable_rule_raises_config_error() -> None:
    """Unknown `--disable-rule` ids fail fast with a config error."""
    with pytest.raises(ConfigError, match="Unknown rule IDs for --disable-rule"):
        resolve_effective_rule_selection(
            loaded_rule_ids=("A", "B"),
            config_rule_overrides={},
            cli_disable_rules=("Z",),
            cli_only_rules=(),
        )


def test_unknown_cli_only_rule_raises_config_error() -> None:
    """Unknown `--only-rules` ids fail fast with a config error."""
    with pytest.raises(ConfigError, match="Unknown rule IDs for --only-rules"):
        resolve_effective_rule_selection(
            loaded_rule_ids=("A", "B"),
            config_rule_overrides={},
            cli_disable_rules=(),
            cli_only_rules=("Z",),
        )


def test_active_rule_overrides_include_only_executed_rules() -> None:
    """Severity overrides remain active only for rules that still execute."""
    selection = resolve_effective_rule_selection(
        loaded_rule_ids=("A", "B"),
        config_rule_overrides={
            "A": RuleOverrideConfig(max_severity="low"),
            "B": RuleOverrideConfig(enabled=False, min_severity="high"),
            "UNKNOWN": RuleOverrideConfig(enabled=False),
        },
        cli_disable_rules=(),
        cli_only_rules=(),
    )

    assert selection.active_rule_overrides == {"A": RuleOverrideConfig(max_severity="low")}
    assert selection.unknown_config_rule_ids == ("UNKNOWN",)
