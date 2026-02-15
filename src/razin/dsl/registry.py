"""Central operation registry for DSL v1 strategies.

Maps strategy names to their implementation functions. Only registered
strategies can be invoked from YAML rules.
"""

from __future__ import annotations

from typing import Any

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

OP_REGISTRY: dict[str, Any] = {
    "url_domain_filter": run_url_domain_filter,
    "ip_address_scan": run_ip_address_scan,
    "key_pattern_match": run_key_pattern_match,
    "field_pattern_match": run_field_pattern_match,
    "entropy_check": run_entropy_check,
    "hint_count": run_hint_count,
    "keyword_in_text": run_keyword_in_text,
    "token_scan": run_token_scan,
    "frontmatter_check": run_frontmatter_check,
    "typosquat_check": run_typosquat_check,
    "bundled_scripts_check": run_bundled_scripts_check,
    "hidden_instruction_scan": run_hidden_instruction_scan,
    "data_sensitivity_check": run_data_sensitivity_check,
}
