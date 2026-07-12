# Configuration

Razin reads config from `<root>/razin.yaml` by default.
Override config path per run with `--config`.

```bash
razin scan -r . -c ./configs/razin.yaml -o output/
```

## Schema overview

Top-level keys currently accepted:

- `profile`
- `allowlist_domains`
- `ignore_default_allowlist`
- `strict_subdomains`
- `denylist_domains`
- `mcp_allowlist_domains`
- `mcp_denylist_domains`
- `tool_prefixes`
- `detectors`
- `typosquat`
- `tool_tier_keywords`
- `data_sensitivity`
- `rule_overrides`
- `skill_globs`
- `max_file_mb`
- `quiet_mode`
- `package_analysis`

Default: `max_file_mb` is `2` when omitted.

## Example `razin.yaml`

```yaml
profile: balanced
allowlist_domains:
  - api.openai.com
ignore_default_allowlist: false
strict_subdomains: false
denylist_domains:
  - "*"
mcp_allowlist_domains:
  - rube.app
mcp_denylist_domains:
  - blocked.example.com
tool_prefixes:
  - RUBE_
  - MCP_
detectors:
  enabled:
    - NET_RAW_IP
    - NET_UNKNOWN_DOMAIN
    - NET_DOC_DOMAIN
    - SECRET_REF
    - EXEC_FIELDS
    - OPAQUE_BLOB
    - BUNDLED_SCRIPTS
    - TYPOSQUAT
    - MCP_REQUIRED
    - MCP_ENDPOINT
    - MCP_DENYLIST
    - MCP_REMOTE_NON_HTTPS
    - MCP_REMOTE_RAW_IP
    - MCP_REMOTE_DENYLIST
    - TOOL_INVOCATION
    - DYNAMIC_SCHEMA
    - AUTH_CONNECTION
    - DATA_SENSITIVITY
    - PROMPT_INJECTION
    - HIDDEN_INSTRUCTION
    - UNICODE_BIDI_CONTROL
    - INSTR_OBFUSCATED_PAYLOAD
    - CONFUSABLE_IDENTIFIER_EXTENDED
    - REMOTE_REFERENCE_RISK
    - PACKAGE_SENSITIVE_NETWORK_FLOW
    - PACKAGE_DATA_EXFILTRATION
    - PACKAGE_REMOTE_CODE_EXECUTION
    - PACKAGE_INVENTORY
    - INCOMPLETE_SCAN
    - DYNAMIC_ANALYSIS_REQUIRED
    - MUTABLE_REMOTE_REFERENCE
    - KNOWN_BAD_DOMAIN
    - KNOWN_BAD_FILE_HASH
    - KNOWN_BAD_INDICATOR
  disabled: []
typosquat:
  baseline:
    - openai-helper
tool_tier_keywords:
  destructive:
    - DELETE
    - DROP
  write:
    - UPDATE
    - CREATE
data_sensitivity:
  high_services:
    - stripe
  medium_services:
    - github
  low_services:
    - wikipedia
  high_keywords:
    - social security
  medium_keywords:
    - confidential
rule_overrides:
  MCP_REQUIRED:
    enabled: false
    max_severity: low
  AUTH_CONNECTION:
    max_severity: low
  KNOWN_BAD_FILE_HASH:
    min_severity: high
skill_globs:
  - "**/SKILL.md"
max_file_mb: 2
package_analysis:
  enabled: true
  max_files: 256
  max_directories: 128
  max_total_mb: 16
  max_file_mb: 2
  max_findings_per_rule: 20
  emit_inventory: false
  known_bad:
    domains: []
    sha256: []
    indicators: []
```

## `package_analysis`

`package_analysis` controls safe, non-executing analysis of files beside each
`SKILL.md`:

- `enabled`: enable whole-package hashing and helper analysis (default: `true`).
- `max_files`: maximum enumerated files per package (default: `256`).
- `max_directories`: maximum traversed directories per package (default: `128`).
- `max_total_mb`: maximum aggregate bytes read per package (default: `16`).
- `max_file_mb`: maximum bytes read from one package member (default: `2`).
- `max_findings_per_rule`: per-package output cap for each package rule (default: `20`).
- `emit_inventory`: emit a capability finding containing the package digest (default: `false`).
- `known_bad.domains`: reviewed malicious domains, with subdomain matching.
- `known_bad.sha256`: full SHA-256 file indicators.
- `known_bad.indicators`: case-insensitive literal indicators.

Limits and unsupported content produce explicit analysis-gap findings. See
[Whole-package analysis](package-analysis.md) for supported languages and
source-to-sink semantics.

## `quiet_mode`

`quiet_mode` controls file-only output for CI and automation pipelines.

Supported keys:

- `enabled`: boolean. Enable quiet mode from config (default: `false`).
- `output_path`: string. File path for quiet output. Required when `enabled` is `true`; validated at config load time.
- `format`: output format. Currently only `jsonl` is supported.
- `include_warnings`: boolean. Include warning records (default: `true`).
- `include_summary`: boolean. Include a final summary record (default: `true`).
- `write_mode`: `overwrite` (default) or `append`.

Example:

```yaml
quiet_mode:
  enabled: true
  output_path: scan-results.jsonl
  format: jsonl
  include_warnings: true
  include_summary: true
  write_mode: overwrite
```

CLI flags `--quiet-mode` and `--quiet-output` override config values for enablement and output path. Behavior fields (`include_warnings`, `include_summary`, `write_mode`) are always loaded from config when available.

## `detectors`

`detectors` provides coarse rule selection before per-rule tuning:

- `enabled`: optional list of rule IDs to allow. If omitted/empty, all loaded rules are eligible.
- `disabled`: optional list of rule IDs to remove from execution.

Behavior details:

- Both DSL and MCP remote rule IDs are supported in detector toggles.
- Unknown detector IDs are ignored with warnings at scan time.
- When both lists are present, `disabled` removes IDs from the enabled set.

## `rule_overrides`

`rule_overrides` controls per-rule policy, including runtime disable and severity bounds.

Supported fields per rule:

- `enabled`: boolean (`true` by default). Set `false` to skip rule execution.
- `max_severity`: one of `high`, `medium`, `low`
- `min_severity`: one of `high`, `medium`, `low`

Behavior details:

- If `enabled: false`, the rule is not executed (no findings, no score contribution).
- Severity override is applied after profile severity resolution for executed rules.
- If a finding exceeds `max_severity`, severity is capped.
- If a finding is below `min_severity`, severity is raised.
- `min_severity` cannot exceed the rule signal kind's maximum claim: capability rules max at low, review and analysis-gap rules max at medium, and only trusted IOC/integrity/attack-chain rules may reach high. Invalid combinations are rejected.
- Capped findings include `severity_override` metadata in output.
- Unknown rule IDs are ignored with warnings at scan time.
- Overrides affect CI gating (`--fail-on`, `--fail-on-score`) because they change final severity/score used by evaluation.
- If both are set for one rule, `min_severity` must be less than or equal to `max_severity`.
- Remote MCP checks also support overrides through `MCP_REMOTE_NON_HTTPS`, `MCP_REMOTE_RAW_IP`, and `MCP_REMOTE_DENYLIST`.

Example:

```yaml
rule_overrides:
  MCP_REQUIRED:
    enabled: false
  AUTH_CONNECTION:
    max_severity: low
  TOOL_INVOCATION:
    max_severity: low
  KNOWN_BAD_FILE_HASH:
    min_severity: high
```

## Profile behavior

| Profile | Legacy aggregate threshold | High threshold | Medium threshold | Local host suppression |
| --- | --- | --- | --- | --- |
| `strict` | 20 | 70 | 40 | off |
| `balanced` (default) | 40 | 80 | 50 | on |
| `audit` | 101 (non-blocking compatibility sentinel) | 70 | 40 | on |

## CLI override precedence

When both config and CLI supply values:

- `--profile` overrides `profile` from file.
- `--max-file-mb` overrides `max_file_mb` from file.
- `--mcp-allowlist` replaces `mcp_allowlist_domains` for that run after normalization.

Rule enable precedence (highest to lowest):

1. `--only-rules`
1. `--disable-rule`
1. `detectors.enabled` / `detectors.disabled`
1. `rule_overrides.<RULE>.enabled`
1. default enabled (all loaded rules)

## Rule source composition

- `--rules-dir` and `--rule-file` are mutually exclusive.
- `--rules-mode replace` loads only custom source.
- `--rules-mode overlay` merges bundled + custom source.
- `--duplicate-policy` is valid only when `--rules-mode overlay`.

```bash
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy override
```

## Validation-first workflow

Before scanning with custom config/rules:

```bash
razin validate-config -r . -c razin.yaml
razin validate-config -r . -R ./enterprise-rules
```

This catches schema/type/conflict issues early and returns deterministic error codes.
