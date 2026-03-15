# Detectors

Razin produces findings from two detector engines:

- DSL rules in `src/razin/dsl/rules/`
- MCP remote endpoint checks in `src/razin/scanner/mcp_remote.py`

Run and group findings by rule:

```bash
razin scan -r . --group-by rule
```

## Detection pipeline

For each discovered `SKILL.md` file, Razin:

1. Parses frontmatter, body text, fields, and keys.
1. Runs all loaded DSL rules and emits `FindingCandidate` objects.
1. Runs MCP remote endpoint checks only for servers referenced by `requires.mcp`.
1. Applies suppression rules to reduce duplicate/overlapping signals.
1. Converts candidates to stable finding IDs and final severity.

## Scoring and severity

- Rule-level scores are in `0..100`.
- Severity thresholds are profile-dependent.
  - `strict`: high >= 70, medium >= 40
  - `balanced`: high >= 80, medium >= 50
  - `audit`: high >= 70, medium >= 40 (aggregate is informational)
- Aggregate scoring keeps the highest finding per `rule_id`; different rules still contribute even when they share the same score.

## Rule classification

Each finding carries a rule classification:

- `security`: directly actionable risk signals
- `informational`: contextual capability signals

CLI filtering options:

- `--security-only` filters output to `security` findings
- `--min-severity` filters by severity level

Classification is additive metadata and does not change rule execution.

## Bundled public rule IDs

Razin currently ships **24** public rule IDs.

| Rule ID | Classification | Score behavior | Confidence | Input surface | Matching logic |
| --- | --- | --- | --- | --- | --- |
| `NET_RAW_IP` | security | 82 public IP, 50 non-public IP | high | extracted fields | Detects raw IPv4/IPv6 literals (`ip_address_scan`). |
| `NET_UNKNOWN_DOMAIN` | security | 55 default, 35 when no allowlist configured, 80 if denylisted | medium/high | code/config fields | URL domain filter, skips IP literals, checks non-allowlisted domains. |
| `NET_DOC_DOMAIN` | security | 15 default, 80 if denylisted | low/high | prose fields | URL domain filter for documentation prose domains only. |
| `MCP_REQUIRED` | informational | 28 | high | frontmatter | Flags `requires.mcp` declaration presence. |
| `MCP_ENDPOINT` | security | 70 | high | extracted fields | Matches MCP-like endpoint paths (`/mcp`) not in MCP allowlist. |
| `MCP_DENYLIST` | security | 90 | high | extracted fields | MCP endpoint domains matching denylist. |
| `MCP_REMOTE_NON_HTTPS` | security | 52 | high | `.mcp.json` for referenced servers | Remote MCP URL uses HTTP (except localhost loopback exceptions). |
| `MCP_REMOTE_RAW_IP` | security | 82 | high | `.mcp.json` for referenced servers | Remote MCP URL host is a public raw IP. |
| `MCP_REMOTE_DENYLIST` | security | 90 | high | `.mcp.json` for referenced servers | Remote MCP URL host matches MCP denylist. |
| `SECRET_REF` | security | 74 key-based branch, 60 env-ref branch | high/medium | keys and fields | Public rule backed by two internal rules: secret-like key names and env secret references. |
| `EXEC_FIELDS` | security | 72 | high | keys | Exact key match on execution terms (`command`, `script`, `exec`, `shell`, `run`). |
| `OPAQUE_BLOB` | security | 54 | medium | fields | Flags long high-entropy or base64-like blobs (`min_length: 80`, `min_entropy: 4.5`). |
| `BUNDLED_SCRIPTS` | security | 58 | medium | filesystem near `SKILL.md` | Presence-only check for executable script extensions (no script content parsing). |
| `TOOL_INVOCATION` | informational | starts at 20, increases with token count/tier, capped at 90 | medium | fields | Consolidated token scan with destructive/write/read tiering. |
| `DYNAMIC_SCHEMA` | informational | 15 | low | raw text | Keyword phrases implying runtime schema/tool discovery. |
| `AUTH_CONNECTION` | informational | 45 | medium | raw text | Strong+weak hint counting with `min_hint_count: 2`, requires strong hint, negation-aware. |
| `PROMPT_INJECTION` | security | 80 | medium | raw text | Prompt-injection phrase detection with strong+weak hint logic, negation-aware. |
| `HIDDEN_INSTRUCTION` | security | 90 | high | raw text | Hidden instruction scan across invisible chars, HTML comments, embedded BOM, and homoglyphs. |
| `DATA_SENSITIVITY` | security | tiered (`high:65`, `medium:40`, `low:15`) + keyword bonus | medium | raw text + parsed fields | Service/keyword-based sensitivity classifier with category inference. |
| `TYPOSQUAT` | security | 76 | medium | frontmatter + derived names | Levenshtein-based similarity check against baseline (`max_distance: 2`, `min_name_length: 5`). |
| `UNICODE_BIDI_CONTROL` | security | 85 base, +7 in code fences, +5 for unpaired overrides | high | raw text | Detects Unicode bidi override/isolate controls (U+202A–U+202E, U+2066–U+2069) indicating Trojan Source risk. |
| `INSTR_OBFUSCATED_PAYLOAD` | security | 78 | high | raw text | Decodes base64 (including URL-safe), hex, and unicode-escape blocks with strong/weak hint matching (`min_hint_matches: 2`, `require_strong: true`). |
| `CONFUSABLE_IDENTIFIER_EXTENDED` | security | 72 base, +5 if frontmatter signal | high | raw text + frontmatter | Mixed-script confusable identifier detection across frontmatter values, body identifiers, and URL hostnames. Deduplicates tokens across surfaces. |
| `REMOTE_REFERENCE_RISK` | security | 62 base, +8 insecure http, 72 unsafe scheme, 68 shortener, 74 fetch-apply | medium | raw text | Detects insecure `http://` URLs, unsafe URI schemes (`data:`, `javascript:`, `ftp:`, etc.), known URL shortener domains, and fetch-and-apply instruction patterns. |

## Detector behavior details

### Domain/network nuances

- `NET_UNKNOWN_DOMAIN` and `NET_DOC_DOMAIN` apply local-host suppression in `balanced`/`audit` profiles.
- `strict_subdomains: true` requires exact domain matches for allowlist checks.
- Denylist matches elevate domain findings to high-risk score behavior.

### MCP precedence and suppression

- Remote MCP checks only evaluate servers actually referenced by `requires.mcp`.
- Remote MCP findings are collapsed to one highest-priority finding per endpoint:
  - `MCP_REMOTE_DENYLIST` > `MCP_REMOTE_RAW_IP` > `MCP_REMOTE_NON_HTTPS`
- For overlapping evidence on the same line, low-value domain findings can be suppressed when `MCP_ENDPOINT` already covers that URL.

### Secret and execution nuances

- `SECRET_REF` merges two internal detectors into one public rule ID.
- Secret key detector skips placeholder/template values to reduce false positives.
- `EXEC_FIELDS` is key-name based and intentionally conservative.

### LLM threat detector nuances

- `PROMPT_INJECTION` requires at least two total hints and at least one strong hint.
- `HIDDEN_INSTRUCTION` detects hidden text vectors not visible in normal markdown rendering.
- `UNICODE_BIDI_CONTROL` detects bidirectional override and isolate control characters that can make displayed text differ from parsed text (Trojan Source). It does not flag legitimate Arabic/Hebrew script content that does not use explicit bidi overrides. When both `UNICODE_BIDI_CONTROL` and `HIDDEN_INSTRUCTION` fire on the same evidence line, the more specific bidi finding suppresses the hidden-instruction finding.
- `INSTR_OBFUSCATED_PAYLOAD` decodes base64 (standard and URL-safe), hex, and unicode-escape blocks bounded by length and candidate budget limits. Decoded content is checked against strong and weak injection hint lists; at least 2 total hint matches with at least 1 strong hint are required by default. Benign encoded content matching only a single weak hint does not trigger. When both `INSTR_OBFUSCATED_PAYLOAD` and `OPAQUE_BLOB` fire on the same evidence line, the obfuscated-payload finding suppresses the opaque-blob finding.
- `CONFUSABLE_IDENTIFIER_EXTENDED` detects mixed-script confusable identifiers across three surfaces: frontmatter values (name, tool, server, etc.), body text identifiers, and URL hostnames. Tokens must mix ASCII with confusable-range characters (Cyrillic, Greek, Letterlike Symbols, Fullwidth Forms) and meet a minimum length of 3 characters. Evidence snippets annotate confusable characters with their Unicode codepoints and names. Frontmatter signals add a +5 score boost. When both `CONFUSABLE_IDENTIFIER_EXTENDED` and `HIDDEN_INSTRUCTION` fire on the same evidence line, the confusable-identifier finding suppresses the hidden-instruction finding.
- `REMOTE_REFERENCE_RISK` scans raw text for four risk categories: insecure `http://` URLs to non-local hosts (+8 boost over base), unsafe URI schemes (`data:`, `javascript:`, `ftp:`, `file:`, etc. at score 72), known URL shortener domains (score 68), and fetch-and-apply instruction language like "curl | sh" or "download and execute" (score 74). Local/reserved hosts (localhost, example.com, `.local` TLD) are exempt from insecure-http detection. The final score is the maximum across all detected signals. When both `REMOTE_REFERENCE_RISK` and `NET_UNKNOWN_DOMAIN`/`NET_DOC_DOMAIN` fire on the same evidence line, the remote-reference finding suppresses the domain finding.

### Typosquat baseline behavior

- If `typosquat.baseline` is absent and at least two skills are discovered, baseline is auto-derived.
- Explicit `typosquat.baseline` disables auto-derivation.

## Tuning detector coverage

Restrict enabled detectors in config when you want focused scans:

```yaml
detectors:
  enabled:
    - NET_RAW_IP
    - NET_UNKNOWN_DOMAIN
    - MCP_REMOTE_NON_HTTPS
    - MCP_ENDPOINT
  disabled: []
```

Then run:

```bash
razin scan -r . --group-by rule
```
