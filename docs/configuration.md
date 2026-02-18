# Configuration

Razin reads config from `<root>/razin.yaml` by default.
Override config path per run with `--config`.

```bash
uv run razin scan -r . -c ./configs/razin.yaml -o output/
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
skill_globs:
  - "**/SKILL.md"
max_file_mb: 2
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
uv run razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy override
```

## Validation first workflow

Before scanning with custom config/rules:

```bash
uv run razin validate-config -r . -c razin.yaml
uv run razin validate-config -r . -R ./enterprise-rules
```

This catches schema/type/conflict issues early and returns deterministic error codes.
