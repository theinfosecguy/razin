# ADR-001: Incremental Architecture Decomposition

## Status

Accepted

## Context

Core source modules have grown beyond comfortable reasoning thresholds. The
six largest production files total over 4,200 LOC and contain multiple
responsibilities each. Test files exceed 3,400 LOC in the four biggest
modules. Key concerns:

- `dsl/ops.py` (1,376 LOC) mixes URL/domain, IP, secret, entropy, token-scan,
  hidden-instruction, frontmatter, typosquat, data-sensitivity, and bundled
  script operations with their private helpers.
- `config.py` (724 LOC) merges data model, loader, normalizer, and validation.
- `scanner/orchestrator.py` (576 LOC) packs config resolution, caching,
  conversion, deduplication, and serialization into one function body.
- `detectors/rules.py` (633 LOC) and `detectors/docs/rules.py` (508 LOC)
  duplicate ~12 private helpers (~200 LOC) with `dsl/ops.py`.
- `tests/dsl/test_dsl.py` (1,691 LOC) covers schema, runtime, rule execution,
  and data-sensitivity in a single file.

## Decision

Decompose large files into focused submodules using compatibility facades so
existing import paths continue to work. Consolidate duplicated helper
functions into shared modules. Reorganize oversized test files by domain.

### Migration rules

1. Existing entry-point files (`config.py`, `dsl/ops.py`,
   `scanner/orchestrator.py`) remain as thin compatibility facades that
   re-export all public names from new submodules.
2. Internal logic moves in small steps; public behavior and import paths are
   preserved.
3. Duplicated private helpers are consolidated into `detectors/common.py` (for
   detector-specific helpers) or `utils/` (for general math/text utilities).
4. Tests are split by domain behavior, not by source file structure.
5. No new features, scoring changes, or output schema changes in this work.

### Source decomposition plan

#### A) `dsl/ops.py` -> `dsl/operations/` package

| New module | Functions moved |
|---|---|
| `operations/url_domain.py` | `run_url_domain_filter`, `_extract_host`, `_any_url`, `_is_mcp_endpoint`, `_skip_ip_addresses`, `_not_allowlisted*`, `_is_denylisted_domain`, `_not_mcp_allowlisted` |
| `operations/ip_entropy.py` | `run_ip_address_scan`, `run_entropy_check`, `_parse_ip_address`, `_is_local_dev_host`, `_extract_raw_ip_addresses`, `_is_non_public_ip`, `_shannon_entropy`, `_looks_like_prose` |
| `operations/text_match.py` | `run_key_pattern_match`, `run_field_pattern_match`, `run_hint_count`, `run_keyword_in_text`, `_hint_is_negated`, `_keyword_in_text`, `_is_non_secret_env_ref`, `_is_placeholder_secret_value` |
| `operations/frontmatter.py` | `run_frontmatter_check` |
| `operations/typosquat.py` | `run_typosquat_check`, `_levenshtein_distance`, `_tokenize_name`, `_service_matches_name` |
| `operations/token_scan.py` | `run_token_scan`, `_classify_token_tier`, `_compute_consolidated_score`, `_build_consolidated_description`, `_service_prefixes`, `_is_service_tool_token` |
| `operations/hidden_instructions.py` | `run_hidden_instruction_scan`, `_detect_zero_width_chars`, `_zwc_evidence`, `_detect_suspicious_html_comments`, `_html_comment_evidence`, `_detect_embedded_bom`, `_embedded_bom_evidence`, `_detect_homoglyphs`, `_homoglyph_evidence`, `_extract_uppercase_tokens`, `_find_confusables_in_token` |
| `operations/data_sensitivity.py` | `run_data_sensitivity_check`, `_infer_category_from_keywords` |
| `operations/filesystem.py` | `run_bundled_scripts_check` |

`dsl/ops.py` becomes a facade importing and re-exporting all `run_*` functions.

#### B) `config.py` -> `config/` package

| New module | Contents |
|---|---|
| `config/model.py` | `RazinConfig` dataclass |
| `config/loader.py` | `load_config()`, `_ensure_string_list`, `_normalize_domains`, `_merge_domains`, `_build_data_sensitivity_config` |
| `config/validator.py` | `validate_config_file()`, `_validate_detectors_block`, `_validate_typosquat_block`, `_validate_tool_tier_block`, `_validate_data_sensitivity_block`, `_suggest_key` |
| `config/fingerprint.py` | `config_fingerprint()`, `effective_detector_ids()` |

`config.py` becomes a facade re-exporting `RazinConfig`, `load_config`,
`config_fingerprint`, `effective_detector_ids`, `validate_config_file`.

#### C) `scanner/orchestrator.py` -> `scanner/pipeline/` package

| New module | Contents |
|---|---|
| `pipeline/cache_utils.py` | `_is_cache_hit`, `_resolve_mcp_dependency_signature`, `_get_or_create_cache_namespace`, `_new_namespace` |
| `pipeline/conversion.py` | `_candidate_to_finding`, `_suppress_redundant_candidates`, `_deserialize_findings`, `_as_severity`, `_as_confidence` |
| `pipeline/config_resolution.py` | `_apply_mcp_allowlist_override`, `_normalize_domain_or_url`, `_resolve_engine`, `_resolve_rule_sources` |

`orchestrator.py` keeps `scan_workspace()` and imports helpers from the
pipeline subpackage.

#### D) Duplicate helper consolidation

Move shared private helpers from `detectors/rules.py` and
`detectors/docs/rules.py` into `detectors/common.py` and `utils/`:

- IP helpers -> `detectors/common.py`
- Math helpers (`_shannon_entropy`, `_levenshtein_distance`) -> `utils/math.py`
- Text helpers (`_looks_like_prose`, `_hint_is_negated`) -> `utils/text.py`
- Token helpers (`_classify_token_tier`) -> `detectors/common.py`

`dsl/ops.py` operations import from these shared locations instead of
duplicating.

### Test decomposition plan

| Current file | Split into |
|---|---|
| `tests/dsl/test_dsl.py` (1,691 LOC) | `tests/dsl/test_schema.py`, `tests/dsl/test_runtime.py`, `tests/dsl/test_rule_execution.py`, `tests/dsl/test_data_sensitivity.py` |
| `tests/detectors/test_detectors.py` (814 LOC) | `tests/detectors/test_network.py`, `tests/detectors/test_secrets.py`, `tests/detectors/test_execution.py`, `tests/detectors/test_typosquat.py`, `tests/detectors/test_bundled_scripts.py` |
| `tests/test_config_validation.py` (461 LOC) | `tests/config/test_validator.py` |
| `tests/test_cli.py` + `tests/cli/test_cli.py` (529 LOC combined) | `tests/cli/test_cli.py` (consolidated) |

### Public API stability

The following import paths must not break:

- `from razin.config import RazinConfig, load_config, config_fingerprint, validate_config_file`
- `from razin.scanner import scan_workspace`
- `from razin.detectors import build_detectors, Detector`
- `from razin.dsl import DslEngine`
- `from razin.dsl.ops import run_*` (via registry)

## Consequences

- Internal file sizes drop below 400 LOC soft cap for most modules.
- Duplicated helpers are consolidated, reducing maintenance surface.
- Compatibility facades preserve all existing import paths.
- Test files become navigable by domain, improving triage speed.
- Guardrail checks prevent future accumulation of mega-files.
