"""DSL operations subpackage.

Contains the individual operation implementations, split by domain.
All ``run_*`` functions are re-exported from this package for
backward compatibility.
"""

from __future__ import annotations

from razin.dsl.operations.data_sensitivity import run_data_sensitivity_check
from razin.dsl.operations.filesystem import run_bundled_scripts_check
from razin.dsl.operations.frontmatter import run_frontmatter_check
from razin.dsl.operations.hidden_instructions import run_hidden_instruction_scan
from razin.dsl.operations.ip_entropy import run_entropy_check, run_ip_address_scan
from razin.dsl.operations.text_match import (
    run_field_pattern_match,
    run_hint_count,
    run_key_pattern_match,
    run_keyword_in_text,
)
from razin.dsl.operations.token_scan import run_token_scan
from razin.dsl.operations.typosquat import run_typosquat_check
from razin.dsl.operations.url_domain import run_url_domain_filter

__all__ = [
    "run_bundled_scripts_check",
    "run_data_sensitivity_check",
    "run_entropy_check",
    "run_field_pattern_match",
    "run_frontmatter_check",
    "run_hidden_instruction_scan",
    "run_hint_count",
    "run_ip_address_scan",
    "run_key_pattern_match",
    "run_keyword_in_text",
    "run_token_scan",
    "run_typosquat_check",
    "run_url_domain_filter",
]
