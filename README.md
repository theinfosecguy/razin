# RAZIN

```text
>_ RAZIN
     // static analysis for LLM skills
```

RAZIN is a local scanner for SKILL.md-defined agent skills.

It performs static analysis only (no execution) and writes deterministic JSON reports.

## Table of Contents

- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Quality Checks](#quality-checks)
- [Config File](#config-file)
- [Outputs](#outputs)

## Requirements

- Python `3.12+`

## Install

```bash
pip install razin
```

Verify:

```bash
razin --help
```

## Usage

Basic scan:

```bash
razin scan --root . --output-dir output/
```

Custom rules directory:

```bash
razin scan --root . --rules-dir ./enterprise-rules --output-dir output/
```

Single rule file:

```bash
razin scan --root . --rule-file ./enterprise-rules/net_unknown_domain.yaml --output-dir output/
```

Specific rule files:

```bash
razin scan --root . \
  --rule-file ./enterprise-rules/net_unknown_domain.yaml \
  --rule-file ./enterprise-rules/mcp_endpoint.yaml \
  --output-dir output/
```

CLI flags:

- `--root <path>`: workspace root to scan
- `--output-dir <path>`: output root for findings and summaries
- `--config <file>`: optional config file path (defaults to `<root>/razin.yaml`)
- `--mcp-allowlist <domain-or-url>`: optional repeatable MCP endpoint/domain allowlist override
- `--engine <dsl>`: detector engine (`dsl` only; removed values: `legacy`, `optionc`, `default`)
- `--rules-dir <path>`: load all custom `*.yaml` DSL rules from this directory
- `--rule-file <path>`: load specific custom `*.yaml` DSL rule file (repeatable)
- `--no-cache`: disable cache reads/writes
- `--max-file-mb <n>`: skip files larger than `n` MB
- `--output-format json`: reserved for future formats (currently only `json`)

Rules source behavior:

- Default mode (no custom flags): bundled rules under `src/razin/dsl/rules/`
- Custom directory mode: `--rules-dir` replaces bundled rules for that scan
- Custom file mode: one or more `--rule-file` values replace bundled rules for that scan
- `--rules-dir` and `--rule-file` are mutually exclusive
- Invalid path, invalid extension, duplicate `rule_id`, and invalid YAML fail fast

## Quality Checks

```bash
uv run isort --check-only src tests
uv run black --check src tests
uv run ruff check src tests
uv run mypy src tests
uv run pytest -q
```

## Config File

Create `razin.yaml` in scan root (or pass with `--config`):

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

Per skill, RAZIN writes:

- `output/<skill-name>/findings.json`
- `output/<skill-name>/summary.json`

Cache file:

- `output/.razin-cache.json`

Skill name derivation precedence:

1. Frontmatter `name` (if present)
2. Nearest folder containing `SKILL.md`
3. Sanitized relative path from scan root
