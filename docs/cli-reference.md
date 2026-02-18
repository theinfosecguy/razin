# CLI reference

Razin exposes two primary commands:

- `razin scan`
- `razin validate-config`

Get command help locally:

```bash
uv run razin scan -h
uv run razin validate-config -h
```

## `razin scan`

Example:

```bash
uv run razin scan -r . -o output/ --profile balanced
```

### Flags

| Flag | Description |
| --- | --- |
| `-h`, `--help` | Show help and exit. |
| `-r`, `--root ROOT` | Workspace root path. |
| `-o`, `--output-dir OUTPUT_DIR` | Output directory root (no files written if omitted). |
| `-c`, `--config CONFIG` | Explicit config file. |
| `-m`, `--mcp-allowlist MCP_ALLOWLIST` | Allowlisted MCP endpoint/domain; repeat for multiple values. |
| `-p`, `--profile {strict,balanced,audit}` | Policy profile selection. |
| `-R`, `--rules-dir RULES_DIR` | Custom DSL rules directory. |
| `-f`, `--rule-file RULE_FILE` | Custom DSL rule file path; repeat for multiple files. |
| `-n`, `--no-cache` | Disable cache reads and writes. |
| `--rules-mode {replace,overlay}` | Rule composition mode (`replace` or `overlay`). |
| `--duplicate-policy {error,override}` | Duplicate `rule_id` behavior for overlay mode. |
| `--max-file-mb MAX_FILE_MB` | Skip `SKILL.md` files larger than this size. |
| `--output-format OUTPUT_FORMAT` | Comma-separated formats: `json`, `csv`, `sarif`. |
| `--no-stdout` | Silence stdout output. |
| `--no-color` | Disable colored output. |
| `-v`, `--verbose` | Show cache stats and diagnostics. |
| `--group-by {skill,rule}` | Group findings by skill or by rule (stdout only). |
| `--fail-on {high,medium,low}` | Exit 1 if any finding meets or exceeds this severity. |
| `--fail-on-score N` | Exit 1 if aggregate score meets or exceeds `N` (0-100). |

### Flag interactions and constraints

Razin enforces several combinations explicitly:

| Combination | Behavior |
| --- | --- |
| `--rules-dir` with `--rule-file` | Invalid. They are mutually exclusive (`argparse` group + preflight validation). |
| `--duplicate-policy` without `--rules-mode overlay` | Invalid. Returns exit code `2` with a configuration error. |
| `--fail-on-score` outside `0..100` | Invalid. Returns exit code `2`. |
| `--output-format` containing empty tokens (for example `json,,csv`) | Invalid. Returns exit code `2`. |
| Unknown output format token | Invalid. Allowed values are only `json`, `csv`, `sarif`. |

### Operational behavior details

- Preflight validation always runs before scanning:
  - config file validation
  - custom rule source validation
- `--group-by` changes stdout rendering only. It does not change JSON/CSV/SARIF artifacts.
- If `--output-dir` is omitted, no scan artifact files are written.
- `--mcp-allowlist` values are normalized to domains and replace `mcp_allowlist_domains` for that run.
- `--profile` provided on CLI overrides `profile` in `razin.yaml` for that run.

### Rule source examples

```bash
# Use only rules from a custom directory (replace bundled)
uv run razin scan -r . -R ./enterprise-rules --rules-mode replace

# Overlay custom rules on bundled rules and fail on duplicate rule IDs
uv run razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy error

# Overlay custom rules and let custom duplicate IDs override bundled rules
uv run razin scan -r . -f ./rules/auth_override.yaml --rules-mode overlay --duplicate-policy override
```

## `razin validate-config`

Example:

```bash
uv run razin validate-config -r . -c razin.yaml
```

### Flags

| Flag | Description |
| --- | --- |
| `-h`, `--help` | Show help and exit. |
| `-r`, `--root ROOT` | Workspace root path. |
| `-c`, `--config CONFIG` | Explicit config file. |
| `-R`, `--rules-dir RULES_DIR` | Custom DSL rules directory. |
| `-f`, `--rule-file RULE_FILE` | Custom DSL rule file path; repeat for multiple files. |

Validation command constraints:

- `--rules-dir` and `--rule-file` are mutually exclusive.
- Validation returns deterministic error codes/messages for config/rule issues.

## Exit codes

For automation and CI:

- `0`: success, thresholds not exceeded
- `1`: scan completed but failed CI threshold (`--fail-on`, `--fail-on-score`) or runtime scanner error
- `2`: CLI/config/preflight validation error

## Common recipes

```bash
# Quiet CI run with both severity and score gates
uv run razin scan -r . --fail-on medium --fail-on-score 50 --no-stdout

# Validate custom rule files only
uv run razin validate-config -r . -f ./rules/custom_1.yaml -f ./rules/custom_2.yaml
```
