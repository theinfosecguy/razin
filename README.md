<h1 align="center">Razin - Static Analysis for LLM Agent Skills</h1>

<p align="center">
<img src="https://github.com/user-attachments/assets/33c42667-0fff-4eac-a2d1-0f6d10441245" alt="razin" width="300" height="300" />
<p align="center">

Razin is a local scanner for SKILL.md-defined agent skills. It performs static analysis only (no execution) and writes deterministic JSON reports.

## Table of Contents

- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Workflow](#workflow)
- [Python (Primary)](#python-primary)
- [Docker (Optional)](#docker-optional)
- [Config File](#config-file)
- [Output Formats](#output-formats)
- [Releasing](#releasing)
- [Outputs](#outputs)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

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
razin scan -r . -o output/
```

Custom rules directory:

```bash
razin scan -r . -R ./enterprise-rules -o output/
```

Single rule file:

```bash
razin scan -r . -f ./enterprise-rules/net_unknown_domain.yaml -o output/
```

Multiple rule files:

```bash
razin scan -r . \
  -f ./enterprise-rules/net_unknown_domain.yaml \
  -f ./enterprise-rules/mcp_endpoint.yaml \
  -o output/
```

Long-form equivalent (for scripts and clarity):

```bash
razin scan --root . --output-dir output/ --profile strict --no-cache
```

CLI flags:

- `-r`, `--root <path>`: workspace root to scan
- `-o`, `--output-dir <path>`: output root for findings and summaries
- `-c`, `--config <file>`: optional config file path (defaults to `<root>/razin.yaml`)
- `-m`, `--mcp-allowlist <domain-or-url>`: optional repeatable MCP endpoint/domain allowlist override
- `-p`, `--profile <strict|balanced|audit>`: policy profile
- `-R`, `--rules-dir <path>`: load all custom `*.yaml` DSL rules from this directory
- `-f`, `--rule-file <path>`: load specific custom `*.yaml` DSL rule file (repeatable)
- `-n`, `--no-cache`: disable cache reads/writes
- `-v`, `--verbose`: show cache stats and diagnostics
- `--rules-mode <replace|overlay>`: rule composition mode (default: `replace`)
- `--duplicate-policy <error|override>`: duplicate rule_id handling in overlay mode (default: `error`)
- `--max-file-mb <n>`: skip files larger than `n` MB
- `--output-format <formats>`: comma-separated output formats: `json`, `csv`, `sarif` (default: `json`)
- `--no-stdout`: silence stdout output
- `--no-color`: disable colored output

Rules source behavior:

- Default mode (no custom flags): bundled rules under `src/razin/dsl/rules/`
- Custom directory mode: `--rules-dir` replaces bundled rules for that scan
- Custom file mode: one or more `--rule-file` values replace bundled rules for that scan
- `--rules-dir` and `--rule-file` are mutually exclusive
- Invalid path, invalid extension, duplicate `rule_id`, and invalid YAML fail fast

Rule composition with `--rules-mode`:

- `replace` (default): custom source replaces bundled rules entirely
- `overlay`: bundled rules are loaded first, then custom rules are merged in

Overlay duplicate handling:

- By default (`--duplicate-policy error`), a custom rule with the same `rule_id` as a bundled rule causes a clear error
- With `--duplicate-policy override`, the custom rule replaces the bundled rule

Overlay examples:

```bash
# Merge enterprise rules on top of bundled rules
razin scan -r . -R ./enterprise-rules --rules-mode overlay -o output/

# Override a specific bundled rule
razin scan -r . -f ./custom_auth.yaml --rules-mode overlay --duplicate-policy override -o output/
```

## Workflow

### Python (Primary)

Use the local Python/uv workflow for day-to-day development:

```bash
uv run razin scan -r . -o output/
uv run pytest -q
uv run ruff check src tests
uv run mypy src tests
```

### Docker (Optional)

Prerequisites:

- Docker Desktop (macOS/Windows) or Docker Engine (Linux)

Build runtime image:

```bash
docker build -t razin:local .
```

Run scanner in Docker:

```bash
docker run --rm razin:local --help
docker run --rm razin:local scan --help

docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  razin:local \
  scan --root /work --output-dir /work/output/docker
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
strict_subdomains: false
detectors:
  enabled:
    - NET_RAW_IP
    - NET_UNKNOWN_DOMAIN
    - NET_DOC_DOMAIN
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

By default, subdomain matching is enabled: allowlisting `github.com` also covers `docs.github.com`. Set `strict_subdomains: true` to require exact domain matches only.

## Output Formats

### JSON (default)

Per-skill JSON files are always written when `--output-dir` is set:

```bash
razin scan -r . -o output/
```

### CSV

Export all findings as a single CSV file:

```bash
razin scan -r . -o output/ --output-format csv
```

Generates `output/findings.csv` with columns: `id`, `skill`, `rule_id`, `severity`, `score`, `confidence`, `path`, `line`, `title`, `description`, `recommendation`.

### SARIF

Export findings as SARIF 2.1.0 for code-scanning integrations:

```bash
razin scan -r . -o output/ --output-format sarif
```

Generates `output/findings.sarif`.

### Multiple formats

Generate all formats in one run:

```bash
razin scan -r . -o output/ --output-format json,csv,sarif
```

## Outputs

Per skill, RAZIN writes:

- `output/<skill-name>/findings.json`
- `output/<skill-name>/summary.json`

Global exports (when selected):

- `output/findings.csv`
- `output/findings.sarif`

Cache file:

- `output/.razin-cache.json`

Skill name derivation precedence:

1. Frontmatter `name` (if present)
2. Nearest folder containing `SKILL.md`
3. Sanitized relative path from scan root

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, quality checks, and PR guidelines.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
