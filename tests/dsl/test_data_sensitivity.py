"""Tests for DATA_SENSITIVITY DSL rule behavior."""

from __future__ import annotations

from pathlib import Path

from razin.config import RazinConfig
from razin.dsl import DslEngine
from razin.parsers import parse_skill_markdown_file

from .conftest import _skill_file


def test_data_sensitivity_stripe_financial(tmp_path: Path) -> None:
    """DATA_SENSITIVITY fires on stripe-automation with financial category."""
    path = _skill_file(
        tmp_path,
        "---\nname: stripe-automation\n---\n# Stripe\n" "Process credit card payments and manage invoices.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="stripe-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "financial" in findings[0].description.lower()
    assert "stripe" in findings[0].description.lower()
    assert findings[0].score >= 65
    assert findings[0].evidence.line is not None
    assert findings[0].evidence.line > 1
    assert "service=" not in findings[0].evidence.snippet
    assert "category_source=service" in findings[0].description
    assert "signal_source=service_text" in findings[0].description


def test_data_sensitivity_gmail_communication(tmp_path: Path) -> None:
    """DATA_SENSITIVITY fires on gmail-automation with communication/PII category."""
    path = _skill_file(
        tmp_path,
        "---\nname: gmail-automation\n---\n# Gmail\n" "Read and send emails. Access personal correspondence.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="gmail-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "communication/pii" in findings[0].description.lower()
    assert "gmail" in findings[0].description.lower()
    assert findings[0].score >= 65
    assert "category_source=service" in findings[0].description
    assert "signal_source=service_text" in findings[0].description


def test_data_sensitivity_nasa_low(tmp_path: Path) -> None:
    """DATA_SENSITIVITY fires on nasa-automation with low severity public-data category."""
    path = _skill_file(
        tmp_path,
        "---\nname: nasa-automation\n---\n# NASA\n" "Access publicly available NASA data.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="nasa-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "public-data" in findings[0].description.lower()
    assert findings[0].score <= 20
    assert "category_source=service" in findings[0].description


def test_data_sensitivity_clean_skill(tmp_path: Path) -> None:
    """DATA_SENSITIVITY does not fire on skills with no service match or keywords."""
    path = _skill_file(
        tmp_path,
        "---\nname: file-organizer\n---\n# File Organizer\n" "Organize files in your workspace by type and date.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="file-organizer", parsed=parsed, config=config)
    assert len(findings) == 0


def test_data_sensitivity_keyword_only(tmp_path: Path) -> None:
    """DATA_SENSITIVITY fires on body keywords even without a service name match."""
    path = _skill_file(
        tmp_path,
        "---\nname: custom-tool\n---\n# Custom\n"
        "This tool handles payment data and credit card information securely.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="custom-tool", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "financial" in findings[0].description.lower()
    assert "payment" in findings[0].description.lower() or "credit card" in findings[0].description.lower()
    assert "category_source=keyword" in findings[0].description
    assert "signal_source=keyword_high" in findings[0].description


def test_data_sensitivity_github_medium(tmp_path: Path) -> None:
    """DATA_SENSITIVITY fires on github-automation with medium sensitivity."""
    path = _skill_file(
        tmp_path,
        "---\nname: github-automation\n---\n# GitHub\n" "Manage private repository permissions and pull requests.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="github-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "source-code" in findings[0].description.lower()
    assert findings[0].score == 40
    assert "signal_source=service_text+keyword_medium" in findings[0].description


def test_data_sensitivity_custom_config(tmp_path: Path) -> None:
    """DATA_SENSITIVITY respects custom service registries from config."""
    from razin.types.config import DataSensitivityConfig

    path = _skill_file(
        tmp_path,
        "---\nname: acme-automation\n---\n# Acme\n" "Integrate with the Acme internal system.\n",
    )
    parsed = parse_skill_markdown_file(path)
    ds_config = DataSensitivityConfig(
        high_services=("acme",),
        medium_services=(),
        low_services=(),
    )
    config = RazinConfig(data_sensitivity=ds_config)
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="acme-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    assert findings[0].score >= 65
    assert "signal_source=service_text" in findings[0].description


def test_data_sensitivity_keyword_bonus_increases_score(tmp_path: Path) -> None:
    """DATA_SENSITIVITY score increases when body contains high-sensitivity keywords."""
    path = _skill_file(
        tmp_path,
        "---\nname: slack-automation\n---\n# Slack\n"
        "Send messages and manage channels. Handle password resets and credential sharing.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="slack-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    # Medium service (40) + keyword bonus (10) = 50
    assert findings[0].score == 50
    assert "signal_source=service_text+keyword_high" in findings[0].description


def test_data_sensitivity_no_substring_service_match(tmp_path: Path) -> None:
    """DATA_SENSITIVITY must not match 'linear' inside 'nonlinear-optimizer'."""
    path = _skill_file(
        tmp_path,
        "---\nname: nonlinear-optimizer\n---\n# Nonlinear Optimizer\n" "Solves nonlinear optimization problems.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="nonlinear-optimizer", parsed=parsed, config=config)
    assert len(findings) == 0


def test_data_sensitivity_token_service_match(tmp_path: Path) -> None:
    """DATA_SENSITIVITY correctly matches 'linear' in 'linear-automation'."""
    path = _skill_file(
        tmp_path,
        "---\nname: linear-automation\n---\n# Linear\n" "Manage confidential issues and projects in Linear.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="linear-automation", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "linear" in findings[0].description.lower()


def test_data_sensitivity_medium_service_without_keywords_is_suppressed(tmp_path: Path) -> None:
    """DATA_SENSITIVITY suppresses medium-tier service matches without keyword context."""
    path = _skill_file(
        tmp_path,
        "---\nname: github-automation\n---\n# GitHub\n" "Manage repositories and pull requests.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="github-automation", parsed=parsed, config=config)
    assert len(findings) == 0


def test_data_sensitivity_no_substring_keyword_match(tmp_path: Path) -> None:
    """DATA_SENSITIVITY must not match keyword 'tax' inside word 'syntax'."""
    path = _skill_file(
        tmp_path,
        "---\nname: code-formatter\n---\n# Code Formatter\n" "Improve syntax highlighting and formatting.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="code-formatter", parsed=parsed, config=config)
    assert len(findings) == 0


def test_data_sensitivity_keyword_at_word_boundary(tmp_path: Path) -> None:
    """DATA_SENSITIVITY matches keyword 'tax' when it appears as a standalone word."""
    path = _skill_file(
        tmp_path,
        "---\nname: finance-tool\n---\n# Finance Tool\n" "Process tax records and generate reports.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="finance-tool", parsed=parsed, config=config)
    assert len(findings) == 1
    assert "tax" in findings[0].description.lower()


def test_data_sensitivity_name_only_service_match_is_suppressed(tmp_path: Path) -> None:
    """DATA_SENSITIVITY does not fire when service appears only in skill name."""
    path = _skill_file(
        tmp_path,
        "---\nname: stripe-automation\n---\n# Utilities Helper\n" "Analyze records without external integrations.\n",
    )
    parsed = parse_skill_markdown_file(path)
    config = RazinConfig()
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="stripe-automation", parsed=parsed, config=config)
    assert len(findings) == 0


def test_data_sensitivity_weak_medium_keywords_do_not_trigger(tmp_path: Path) -> None:
    """DATA_SENSITIVITY ignores weak medium keywords without stronger context."""
    from razin.types.config import DataSensitivityConfig

    path = _skill_file(
        tmp_path,
        "---\nname: custom-automation\n---\n# Custom\n" "Share internal notes with employee updates.\n",
    )
    parsed = parse_skill_markdown_file(path)
    ds_config = DataSensitivityConfig(
        high_services=(),
        medium_services=(),
        low_services=(),
        high_keywords=(),
        medium_keywords=("internal", "employee"),
    )
    config = RazinConfig(data_sensitivity=ds_config)
    engine = DslEngine(rule_ids=frozenset({"DATA_SENSITIVITY"}))
    findings = engine.run_all(skill_name="custom-automation", parsed=parsed, config=config)
    assert len(findings) == 0
