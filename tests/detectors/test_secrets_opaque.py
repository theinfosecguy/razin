"""Tests for SECRET_REF and OPAQUE_BLOB detectors."""

from __future__ import annotations

from pathlib import Path

from razin.config import RazinConfig
from razin.detectors.rules import OpaqueBlobDetector, SecretRefDetector
from razin.parsers import parse_skill_markdown_file

from .conftest import _skill_file


def test_prose_with_tool_names_not_flagged(tmp_path: Path) -> None:
    """Long prose line with UPPER_SNAKE_CASE tool names is NOT opaque."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "Use `SENDGRID_ADD_A_SINGLE_RECIPIENT_TO_A_LIST` to add a recipient -- "
        "this legacy API requires the `recipient_id` to be Base64-encoded.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_markdown_table_row_not_flagged(tmp_path: Path) -> None:
    """Markdown table rows (long with pipes and backticks) are not opaque."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "| Create Single Send | `SENDGRID_CREATE_SINGLE_SEND` | "
        "`name`, `email__config__*`, `send_at` | Creates a new single send |\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_actual_base64_blob_still_flagged(tmp_path: Path) -> None:
    """Genuine base64 blob without spaces should still trigger."""
    blob = "QUFB" * 25  # 100 chars of repeating base64
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n{blob}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "OPAQUE_BLOB"


def test_high_entropy_no_spaces_still_flagged(tmp_path: Path) -> None:
    """Dense hex-like string without spaces triggers."""
    blob = "a1b2c3d4e5f6" * 10  # 120 chars, high entropy, no spaces
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n{blob}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "OPAQUE_BLOB"


def test_short_value_ignored(tmp_path: Path) -> None:
    """Values shorter than OPAQUE_MIN_LENGTH are never flagged."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nshort value\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_api_token_env_ref_flagged(tmp_path: Path) -> None:
    """${API_TOKEN} is clearly a secret reference."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\ntoken: ${API_TOKEN}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert any(f.rule_id == "SECRET_REF" for f in findings)


def test_dollar_add_operator_not_flagged(tmp_path: Path) -> None:
    """$add is an API operator, not a secret."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" 'Use "$add": {"login_count": 1} to increment the counter.\n',
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_dollar_set_operator_not_flagged(tmp_path: Path) -> None:
    """$set and $setOnce are API operators, not secrets."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "$set overwrites existing values; $setOnce only sets if not already set.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_secret_key_in_frontmatter_not_in_body_fields(tmp_path: Path) -> None:
    """Keys in frontmatter are not extracted as body fields after B1 fix."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\napi_key: placeholder\n---\n# Docs\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_placeholder_secret_value_not_flagged(tmp_path: Path) -> None:
    """Placeholder values like CHANGEME are not flagged."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\npassword: CHANGEME\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_secret_placeholder_in_code_block_not_flagged(tmp_path: Path) -> None:
    """Placeholder secrets in code blocks are not flagged."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n~~~yaml\napiKey: your-api-key\n~~~\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings
