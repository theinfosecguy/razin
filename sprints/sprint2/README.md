# Sprint 2: Rule Disable Controls via CLI and Config

Allow teams to disable specific rules without editing custom DSL files. Add disable controls in both `razin.yaml` and CLI, with deterministic precedence and clear reporting.

## Scope

Focus areas:
- Disable rules from config (`rule_overrides.<RULE>.enabled: false`)
- Disable rules from CLI (`--disable-rule RULE_ID`, repeatable)
- Disable-all then allowlist mode from CLI (`--only-rules RULE_ID`, repeatable)
- Deterministic precedence between config and CLI
- Output/report metadata showing active disable controls

Out-of-scope:
- Rule authoring or DSL language changes beyond enable/disable gating
- Per-skill rule targeting
- Time-based or environment-based conditional rule toggles

## Problem

Today users can tune severity but cannot disable a single noisy rule without editing custom rule files. That forces heavy workflows for a simple policy need.

## Goals

- Disable one or more rules directly in `razin.yaml`
- Temporarily disable rules per run via CLI
- Keep behavior deterministic and explicit
- Preserve existing defaults when no new disable controls are used

## Epic 1: Config disable controls

### Task 1.1 Add `enabled` to `rule_overrides`

Extend config schema:

```yaml
rule_overrides:
  MCP_REQUIRED:
    enabled: false
```

Rules:
- `enabled` type must be boolean
- Default is `true` when omitted
- Unknown rule IDs warn and continue

Acceptance criteria:
- Valid config parses with `enabled: false`
- Invalid non-boolean values fail validation
- Unknown rule IDs emit warning, not hard failure

### Task 1.2 Apply config disable before execution

Disable controls should prevent rule execution at runtime, not just hide output.

Acceptance criteria:
- Disabled rule produces zero findings
- Aggregate score and fail checks exclude disabled rules
- Cache fingerprint changes when disable config changes

## Epic 2: CLI disable controls

### Task 2.1 Add `--disable-rule` (repeatable)

Examples:

```bash
razin scan -r . --disable-rule MCP_REQUIRED --disable-rule AUTH_CONNECTION
```

Acceptance criteria:
- Repeatable parsing works
- Unknown rule IDs reported clearly
- Runtime execution excludes disabled rules

### Task 2.2 Add `--only-rules` (repeatable)

Examples:

```bash
razin scan -r . --only-rules SECRET_REF --only-rules OPAQUE_BLOB
```

Behavior:
- Only listed rules execute
- Mutually exclusive with `--disable-rule`

Acceptance criteria:
- Mutual exclusion enforced by CLI parsing
- Runtime executes only listed rules
- Fail-on logic uses resulting executed-rule findings

## Epic 3: Precedence and interaction model

Precedence order (highest to lowest):
1. `--only-rules`
2. `--disable-rule`
3. `rule_overrides.<RULE>.enabled`
4. Default enabled

Interpretation:
- `--only-rules` is explicit allowlist for one run
- `--disable-rule` subtracts from otherwise enabled set
- config `enabled: false` is baseline policy

Acceptance criteria:
- Documented and tested precedence matrix
- Deterministic rule set computed once per run

## Epic 4: Reporting and transparency

Add runtime metadata to summary/stdout/SARIF/JSON:
- `rules_executed`
- `rules_disabled`
- `disable_sources` (`config`, `cli-disable`, `cli-only`)

Acceptance criteria:
- Reviewers can see which rules were skipped and why
- Metadata appears in all major output surfaces

## Interaction matrix

| Scenario | Expected behavior |
| --- | --- |
| Config disables `MCP_REQUIRED` | Rule never runs |
| CLI `--disable-rule MCP_REQUIRED` | Rule never runs for that invocation |
| Config disables + CLI `--only-rules MCP_REQUIRED` | `--only-rules` wins; rule runs |
| CLI `--only-rules A --disable-rule B` | Invalid (mutually exclusive) |
| Unknown rule in config disable | Warning, continue |
| Unknown rule in CLI disable | Validation/config error with clear message |

## Testing expectations

- Unit tests for config parsing/validation of `enabled`
- Unit tests for CLI parsing and mutual exclusion
- Unit tests for effective rule-set computation and precedence
- Integration tests proving disabled rules produce no findings
- Cache invalidation tests when disable controls change
- Snapshot tests for new output metadata

## Deliverables

- CLI flags: `--disable-rule`, `--only-rules`
- Config support: `rule_overrides.<RULE>.enabled`
- Runtime rule selection pipeline with precedence
- Output metadata for executed/disabled rules
- Full docs updates in MkDocs (CLI, config, CI, detectors)
- Comprehensive tests
