# Architecture Map

This document describes the module layout, responsibilities, and boundaries of the Razin codebase.

## Package overview

```
src/razin/
  cli/            CLI entry point (argparse, exit codes, stdout formatting)
  config/         Configuration loading, validation, fingerprinting
  constants/      All project-wide constants (no logic)
  detectors/      Built-in detector rules and YAML-driven rule engine
  dsl/            Rule DSL: schema, compiler, runtime, operations
  exceptions/     All custom exception classes
  io/             File and JSON I/O helpers
  model/          Core data model (SkillFile, Finding, ScanResult)
  parsers/        SKILL.md parser (YAML frontmatter + markdown body)
  reporting/      Output writers (JSON, CSV, SARIF, stdout)
  scanner/        Workspace scanning orchestration, caching, discovery
  types/          Shared type aliases and typed dicts
  utils/          Small stateless utilities (naming helpers)
```

## Module responsibilities

### cli/

- `main.py` -- `build_parser()`, `main()` entry point, argument validation, stdout summary rendering.
- Depends on: config, scanner, reporting, model, exceptions.

### config/

Decomposed from a single `config.py` into a focused package:

- `model.py` -- `RazinConfig` frozen dataclass and domain-merge logic.
- `loader.py` -- `load_config()`: YAML loading, profile merging, defaults.
- `validator.py` -- `validate_config_file()`: structural validation of config YAML.
- `fingerprint.py` -- `config_fingerprint()`, `effective_detector_ids()`: deterministic hashing for cache invalidation.
- `__init__.py` -- Compatibility facade re-exporting all public names so `from razin.config import X` keeps working.

### constants/

One module per domain (branding, cache, detectors, domains, scoring, etc.). No logic, only typed constants. Every constant has an explicit type hint.

### detectors/

- `base.py` -- `Detector` protocol / base class.
- `common.py` -- Shared helpers (domain extraction, allowlist matching, evidence building).
- `rules.py` -- Core detector implementations (NET_RAW_IP, SECRET_REF, EXEC_FIELDS, OPAQUE_BLOB, TYPOSQUAT, NET_UNKNOWN_DOMAIN).
- `docs/rules.py` -- Doc-surface detectors (MCP_REQUIRED, MCP_ENDPOINT, MCP_DENYLIST, TOOL_INVOCATION, DYNAMIC_SCHEMA, AUTH_CONNECTION, EXTERNAL_URLS).
- `yaml_rules/` -- YAML-driven rule engine (loader, schema, strategies, engine).

### dsl/

- `schema.py` -- Rule YAML schema definition and validation.
- `compiler.py` -- Compile parsed YAML rules into executable rule objects.
- `runtime.py` -- DSL engine: load rules, execute against skill files, collect candidates.
- `validation.py` -- Rule-file structural validation.
- `context.py`, `registry.py`, `errors.py` -- Supporting infrastructure.
- `ops.py` -- Compatibility facade for operations.
- `operations/` -- Decomposed operation implementations:
  - `shared.py` -- Common helpers used across operations.
  - `url_domain.py` -- `run_url_domain_filter`.
  - `ip_entropy.py` -- `run_ip_address_scan`, `run_entropy_check`.
  - `text_match.py` -- `run_key_pattern_match`, `run_field_pattern_match`, `run_hint_count`, `run_keyword_in_text`.
  - `frontmatter.py` -- `run_frontmatter_check`.
  - `typosquat.py` -- `run_typosquat_check`.
  - `token_scan.py` -- `run_token_scan`.
  - `hidden_instructions.py` -- `run_hidden_instruction_scan`.
  - `data_sensitivity.py` -- `run_data_sensitivity_check`.
  - `filesystem.py` -- `run_bundled_scripts_check`.

### scanner/

- `orchestrator.py` -- `scan_workspace()` main entry point, compatibility facade for pipeline helpers.
- `discovery.py` -- File discovery by glob patterns.
- `cache.py` -- SHA256+mtime scan cache.
- `score.py` -- Probabilistic OR aggregation, severity thresholds.
- `mcp_remote.py` -- MCP config file resolution.
- `pipeline/` -- Decomposed orchestration helpers:
  - `cache_utils.py` -- Cache hit checks, namespace management, MCP dependency signatures.
  - `conversion.py` -- Candidate-to-finding conversion, deduplication, deserialization.
  - `config_resolution.py` -- MCP allowlist overrides, domain normalization, engine/rule-source resolution.

### reporting/

- `writer.py` -- Base writer and JSON output.
- `csv_writer.py` -- CSV output format.
- `sarif_writer.py` -- SARIF output format.
- `stdout.py` -- Rich terminal summary.

### model/

- `entities.py` -- `SkillFile`, `Finding`, `ScanResult`, `DetectorCandidate` and related frozen dataclasses.

## Compatibility facades

Three source files serve as backward-compatible facades after decomposition:

| Facade | Package | Purpose |
|--------|---------|---------|
| `config/__init__.py` | `config/` | Re-exports `RazinConfig`, `load_config`, `validate_config_file`, `config_fingerprint`, `effective_detector_ids` |
| `dsl/ops.py` | `dsl/operations/` | Re-exports all `run_*` operation functions |
| `scanner/orchestrator.py` | `scanner/pipeline/` | Contains `scan_workspace()` and re-exports pipeline helpers with private-name aliases |

Existing imports like `from razin.config import load_config` continue to work unchanged.

## File-size guardrails

A guardrail script (`scripts/check_file_sizes.py`) enforces size caps:

| Category | Soft cap | Hard cap |
|----------|----------|----------|
| Source (`src/razin/`) | 400 LOC | 700 LOC |
| Tests (`tests/`) | 500 LOC | 900 LOC |

LOC counts exclude blank lines and comment-only lines. Soft-cap violations produce warnings; hard-cap violations fail CI.

## Test layout

```
tests/
  cli/              CLI argument parsing and main() behavior
  detectors/        Detector rule tests by domain
    test_network.py       NET_RAW_IP, NET_UNKNOWN_DOMAIN, NET_DOC_DOMAIN
    test_doc_surface.py   MCP_*, TOOL_INVOCATION, DYNAMIC_SCHEMA, AUTH_CONNECTION, EXTERNAL_URLS, TYPOSQUAT
    test_secrets_opaque.py SECRET_REF, OPAQUE_BLOB
    test_common.py        Shared detector helpers
    test_detectors.py     Integration tests
    test_yaml_detectors.py YAML rule engine tests
  dsl/              DSL tests by concern
    test_schema.py        Schema validation and compiler
    test_runtime.py       Engine loading, parity, scan integration
    test_rule_execution.py Individual rule execution
    test_data_sensitivity.py DATA_SENSITIVITY rules
  integration/      End-to-end scan workspace tests
  reporting/        Output writer tests
  scanner/          Cache, discovery, orchestrator, score tests
  fixtures/         Test data and expected outputs
```

Test modules mirror source module boundaries. Each `conftest.py` provides shared helpers scoped to its directory.
