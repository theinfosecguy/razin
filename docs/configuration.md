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
    max_severity: low
  AUTH_CONNECTION:
    max_severity: low
  SECRET_REF:
    min_severity: high
skill_globs:
  - "**/SKILL.md"
max_file_mb: 2
```

## `rule_overrides`

`rule_overrides` lets you cap severity for specific rule IDs without disabling them.

Supported fields per rule:

- `max_severity`: one of `high`, `medium`, `low`
- `min_severity`: one of `high`, `medium`, `low`

Behavior details:

- Override is applied after profile severity resolution.
- If a finding exceeds `max_severity`, severity is capped.
- If a finding is below `min_severity`, severity is raised.
- Capped findings include `severity_override` metadata in output.
- Unknown rule IDs are ignored with warnings at scan time.
- Overrides affect CI gating (`--fail-on`, `--fail-on-score`) because they change final severity/score used by evaluation.
- If both are set for one rule, `min_severity` must be less than or equal to `max_severity`.

Example:

```yaml
rule_overrides:
  MCP_REQUIRED:
    max_severity: low
  TOOL_INVOCATION:
    max_severity: low
  SECRET_REF:
    min_severity: high
```

## Profile behavior

| Profile | Aggregate min rule score | High threshold | Medium threshold | Local host suppression |
| --- | --- | --- | --- | --- |
| `strict` | 20 | 70 | 40 | off |
| `balanced` (default) | 40 | 80 | 50 | on |
| `audit` | 101 (informational aggregate) | 70 | 40 | on |

## CLI override precedence

When both config and CLI supply values:

- `--profile` overrides `profile` from file.
- `--max-file-mb` overrides `max_file_mb` from file.
- `--mcp-allowlist` replaces `mcp_allowlist_domains` for that run after normalization.

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
