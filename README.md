# Raisin

Raisin is a local scanner for SKILL.md-defined agent skills.

It performs static analysis only (no execution) and writes deterministic JSON reports.

## Requirements

- Python `3.12+`
- `uv` (recommended for development workflows)

## Install

Development install:

```bash
uv sync --dev
```

Run via `uv`:

```bash
uv run raisin --help
```

## Usage

Basic scan:

```bash
uv run raisin scan --root . --output-dir output/
```

Custom rules directory:

```bash
uv run raisin scan --root . --rules-dir ./enterprise-rules --output-dir output/
```

Single rule file:

```bash
uv run raisin scan --root . --rule-file ./enterprise-rules/net_unknown_domain.yaml --output-dir output/
```

Specific rule files:

```bash
uv run raisin scan --root . \
  --rule-file ./enterprise-rules/net_unknown_domain.yaml \
  --rule-file ./enterprise-rules/mcp_endpoint.yaml \
  --output-dir output/
```

CLI flags:

- `--root <path>`: workspace root to scan
- `--output-dir <path>`: output root for findings and summaries
- `--config <file>`: optional config file path (defaults to `<root>/raisin.yaml`)
- `--mcp-allowlist <domain-or-url>`: optional repeatable MCP endpoint/domain allowlist override
- `--engine <dsl>`: detector engine (`dsl` only; removed values: `legacy`, `optionc`, `default`)
- `--rules-dir <path>`: load all custom `*.yaml` DSL rules from this directory
- `--rule-file <path>`: load specific custom `*.yaml` DSL rule file (repeatable)
- `--no-cache`: disable cache reads/writes
- `--max-file-mb <n>`: skip files larger than `n` MB
- `--output-format json`: reserved for future formats (currently only `json`)

Rules source behavior:

- Default mode (no custom flags): bundled rules under `src/raisin/dsl/rules/`
- Custom directory mode: `--rules-dir` replaces bundled rules for that scan
- Custom file mode: one or more `--rule-file` values replace bundled rules for that scan
- `--rules-dir` and `--rule-file` are mutually exclusive
- Invalid path, invalid extension, duplicate `rule_id`, and invalid YAML fail fast

## Config File

Create `raisin.yaml` in scan root (or pass with `--config`):

```yaml
allowlist_domains:
  - api.openai.com
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
    - SECRET_REF
    - EXEC_FIELDS
    - OPAQUE_BLOB
    - TYPOSQUAT
    - BUNDLED_SCRIPTS
    - MCP_REQUIRED
    - MCP_ENDPOINT
    - MCP_DENYLIST
    - TOOL_INVOCATION
    - DYNAMIC_SCHEMA
    - AUTH_CONNECTION
    - EXTERNAL_URLS
  disabled: []
typosquat:
  baseline:
    - openai-helper
skill_globs:
  - "**/SKILL.md"
max_file_mb: 2
```

## Outputs

Per skill, Raisin writes:

- `output/<skill-name>/findings.json`
- `output/<skill-name>/summary.json`

Cache file:

- `output/.raisin-cache.json`

Skill name derivation precedence:

1. Frontmatter `name` (if present)
2. Nearest folder containing `SKILL.md`
3. Sanitized relative path from scan root
