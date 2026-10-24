# Razin documentation

Razin is a static analysis scanner for `SKILL.md`-defined agent skills.
It scans skill definitions, applies detector rules, and writes deterministic reports.

These docs describe the 1.6.0 checkout. PyPI currently provides 1.5.0; install
from this repository with `pip install .` to use the documented 1.6.0 commands.

## Quick start

```bash
razin scan -r . -o output/
```

## What to read next

- New users: [Getting Started](getting-started.md)
- Daily CLI usage: [CLI Reference](cli-reference.md)
- Policy tuning: [Configuration](configuration.md)
- Rule coverage: [Detectors](detectors.md)
- CI integration: [CI and Exit Codes](ci-and-exit-codes.md)
- Deployment and local parity: [Docker](docker.md)
- Optional sealed execution-plan provenance: [Sandbox Verification](sandbox-verification.md)
- Common failures: [Troubleshooting](troubleshooting.md)

## Canonical docs policy

- `docs/` is the canonical source for full documentation.
- Root `README.md` is quick start only and links here for full details.
