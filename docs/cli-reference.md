# CLI reference

Razin exposes two primary commands:

- `razin scan`
- `razin validate-config`

Get command help locally:

```bash
razin scan -h
razin validate-config -h
```

## `razin scan`

Example:

```bash
razin scan -r . -o output/ --profile balanced
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
| `--disable-rule RULE_ID` | Disable a public `rule_id` for this invocation; repeat for multiple values. |
| `--only-rules RULE_ID` | Execute only listed public `rule_id` values; repeat for multiple values. |
| `--max-file-mb MAX_FILE_MB` | Skip `SKILL.md` files larger than this size. |
| `--output-format OUTPUT_FORMAT` | Comma-separated formats: `json`, `csv`, `sarif`. |
| `--no-stdout` | Silence stdout output. |
| `--no-color` | Disable colored output. |
| `-v`, `--verbose` | Show cache stats and diagnostics. |
| `--group-by {skill,rule}` | Group findings by skill or by rule (stdout only). |
| `--min-severity {high,medium,low}` | Output filter: show findings at/above this severity in stdout and artifact formats. |
| `--security-only` | Output filter: show only findings where classification is `security`. |
| `--summary-only` | Stdout-only mode: show summary block, no finding rows. |
| `--fail-on {high,medium,low}` | Exit 1 if any finding meets or exceeds this severity. |
| `--fail-on-score N` | Exit 1 if aggregate score meets or exceeds `N` (0-100). |

### Flag interactions and constraints

| Combination | Behavior |
| --- | --- |
| `--rules-dir` with `--rule-file` | Invalid. They are mutually exclusive (`argparse` group + preflight validation). |
| `--duplicate-policy` without `--rules-mode overlay` | Invalid. Returns exit code `2` with a configuration error. |
| `--disable-rule` with `--only-rules` | Invalid. They are mutually exclusive. |
| `--fail-on-score` outside `0..100` | Invalid. Returns exit code `2`. |
| `--output-format` containing empty tokens (for example `json,,csv`) | Invalid. Returns exit code `2`. |
| Unknown output format token | Invalid. Allowed values are only `json`, `csv`, `sarif`. |
| `--summary-only` with `--group-by` | `--summary-only` wins; no table is rendered. |
| `--min-severity` with `--security-only` | Both filters are applied to stdout and artifact outputs. |
| `--min-severity` / `--security-only` with `--fail-on` / `--fail-on-score` | Exit logic uses all findings from the scan, not filtered output. |

### Operational behavior details

- Preflight validation always runs before scanning:
  - config file validation
  - custom rule source validation
- `--group-by` changes stdout rendering only. It does not regroup JSON/CSV/SARIF artifacts.
- If `--output-dir` is omitted, no scan artifact files are written.
- `--mcp-allowlist` values are normalized to domains and replace `mcp_allowlist_domains` for that run.
- `--profile` provided on CLI overrides `profile` in `razin.yaml` for that run.
- `--summary-only` is stdout-only. File artifacts are still written normally.
- Unknown rule IDs in `--disable-rule` / `--only-rules` return a configuration error.

### Filter examples

```bash
# Show only medium/high findings in stdout and output artifacts
razin scan -r . -o output/ --min-severity medium

# Show only security-classified findings
razin scan -r . -o output/ --security-only

# Combined semantic + severity filtering
razin scan -r . -o output/ --security-only --min-severity medium

# Summary-only CI log while still writing artifacts
razin scan -r . -o output/ --summary-only --fail-on medium
```

### Rule source examples

```bash
# Use only rules from a custom directory (replace bundled)
razin scan -r . -R ./enterprise-rules --rules-mode replace

# Overlay custom rules on bundled rules and fail on duplicate rule IDs
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy error

# Overlay custom rules and let custom duplicate IDs override bundled rules
razin scan -r . -f ./rules/auth_override.yaml --rules-mode overlay --duplicate-policy override
```

For rule authoring details, see [How to write custom rules](custom-rules.md).

### Rule selection examples

```bash
# Disable noisy rules for one run
razin scan -r . --disable-rule MCP_REQUIRED --disable-rule AUTH_CONNECTION

# Run only two rules
razin scan -r . --only-rules SECRET_REF --only-rules OPAQUE_BLOB
```

## `razin validate-config`

Example:

```bash
razin validate-config -r . -c razin.yaml
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
- Use validation first when authoring rulepacks. See [How to write custom rules](custom-rules.md).

## Exit codes

For automation and CI:

- `0`: success, thresholds not exceeded
- `1`: scan completed but failed CI threshold (`--fail-on`, `--fail-on-score`) or runtime scanner error
- `2`: CLI/config/preflight validation error

## Common recipes

```bash
# Quiet CI run with both severity and score gates
razin scan -r . --fail-on medium --fail-on-score 50 --no-stdout

# Validate custom rule files only
razin validate-config -r . -f ./rules/custom_1.yaml -f ./rules/custom_2.yaml
```
