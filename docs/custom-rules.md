# Custom rules

Use custom DSL rule files when you need policy checks beyond the bundled detector set.

## Rule file shape (DSL v1)

Each custom rule is a YAML mapping with required top-level fields:

- `rule_id`
- `version` (must be `1`)
- `metadata`
- `scoring`
- `match`

Optional top-level fields:

- `public_rule_id`
- `dedupe`
- `profiles`

### `metadata` fields

Required:

- `title`
- `recommendation`
- `confidence` (`low`, `medium`, `high`)
- at least one of:
  - `description`
  - `description_template`

Optional:

- `classification` (`security`, `informational`)

### `scoring` fields

Required:

- `base_score` (integer `0..100`)

### `match` fields

Required:

- `source`:
  - `fields`
  - `keys`
  - `raw_text`
  - `frontmatter`
  - `file_system`
- `strategy`:
  - `url_domain_filter`
  - `ip_address_scan`
  - `key_pattern_match`
  - `field_pattern_match`
  - `entropy_check`
  - `hint_count`
  - `keyword_in_text`
  - `token_scan`
  - `frontmatter_check`
  - `typosquat_check`
  - `bundled_scripts_check`
  - `hidden_instruction_scan`
  - `data_sensitivity_check`

## Source and strategy matrix

The engine validates allowed `source` values and `strategy` values. In practice, bundled rules use these pairings:

| Source | Strategy | Typical use |
| --- | --- | --- |
| `fields` | `url_domain_filter`, `ip_address_scan`, `field_pattern_match`, `entropy_check`, `token_scan` | URLs, IPs, regex patterns, entropy, token scans in parsed fields |
| `keys` | `key_pattern_match` | key-name pattern checks |
| `raw_text` | `hint_count`, `keyword_in_text`, `hidden_instruction_scan`, `data_sensitivity_check` | prose-level pattern detection |
| `frontmatter` | `frontmatter_check`, `typosquat_check` | frontmatter requirements and name similarity checks |
| `file_system` | `bundled_scripts_check` | presence checks for bundled scripts |

## Minimal rule example

```yaml
rule_id: CUSTOM_RUNTIME_DISCOVERY
version: 1
metadata:
  title: "Runtime discovery instruction"
  description: "Docs include instructions to discover capabilities at runtime."
  recommendation: "Prefer pinned and reviewed capability definitions."
  confidence: low
  classification: informational
scoring:
  base_score: 20
match:
  source: raw_text
  strategy: keyword_in_text
  hints:
    - "discover tools"
    - "discover schema"
    - "before execution"
  first_match_only: true
dedupe: false
```

## Advanced rule example

```yaml
rule_id: CUSTOM_AUTH_HINTS_STRICT
public_rule_id: AUTH_CONNECTION
version: 1
metadata:
  title: "Auth/connection requirements in docs"
  description: "Docs include authentication or connection setup requirements."
  recommendation: "Review auth flows, token scope, and connection trust boundaries."
  confidence: medium
  classification: informational
scoring:
  base_score: 45
match:
  source: raw_text
  strategy: hint_count
  strong_hints:
    - "authenticate"
    - "oauth"
    - "authorization"
  weak_hints:
    - "api key"
    - "token"
    - "connection"
  min_hint_count: 2
  require_strong: true
  negation_aware: true
dedupe: false
profiles:
  strict:
    score_override: 60
  audit:
    score_override: 35
```

Notes:

- `public_rule_id` lets multiple internal rules report under one public rule ID.
- `profiles.<name>.score_override` supports `strict`, `balanced`, and `audit` with values in `0..100`.

## Validate-first workflow

Validate custom rules before scanning:

```bash
# Validate one file
razin validate-config -r . -f ./rules/custom_runtime_discovery.yaml

# Validate all .yaml rules in a directory
razin validate-config -r . -R ./rules
```

Then run scans with your rulepack:

```bash
# Use only custom rules
razin scan -r . -R ./rules --rules-mode replace

# Merge custom + bundled rules, fail on duplicate rule IDs
razin scan -r . -R ./rules --rules-mode overlay --duplicate-policy error

# Merge custom + bundled rules, custom duplicate IDs override bundled
razin scan -r . -R ./rules --rules-mode overlay --duplicate-policy override
```

## Authoring tips

- Start from a bundled rule in `src/razin/dsl/rules/` and modify one behavior at a time.
- Keep `rule_id` stable after rollout so downstream reporting and CI policies remain deterministic.
- Use `validate-config` in CI to catch YAML/schema errors before scans run.
