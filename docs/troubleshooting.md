# Troubleshooting

## Non-UTF8 `SKILL.md` parse failures

Symptom:

- Warnings mentioning invalid UTF-8 or parse errors for `SKILL.md`.

Fix:

```bash
file -I path/to/SKILL.md
iconv -f ISO-8859-1 -t UTF-8 path/to/SKILL.md > /tmp/SKILL.md && mv /tmp/SKILL.md path/to/SKILL.md
```

Then re-run:

```bash
razin scan -r . -o output/
```

## Read-only output path errors

Symptom:

- `Output directory is not writable` before scan starts.

Fix:

```bash
mkdir -p output
chmod u+w output
razin scan -r . -o output/
```

## Custom rule YAML errors

Symptom:

- Invalid YAML, invalid schema, or invalid rule operation errors when using custom rules.

Fix:

```bash
razin validate-config -r . -R ./enterprise-rules
razin scan -r . -R ./enterprise-rules --rules-mode replace
```

Validate one file directly:

```bash
razin validate-config -r . -f ./enterprise-rules/custom_rule.yaml
```

## Duplicate rule IDs in overlay mode

Symptom:

- Overlay scans fail with duplicate `rule_id` conflicts.

Fix options:

```bash
# Fail fast and keep IDs unique
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy error

# Allow custom rule to replace bundled rule
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy override
```

## Docs build failures

Symptom:

- CI fails on docs checks.

Fix:

```bash
uv run mkdocs build --strict
uv run mdformat README.md docs
```
