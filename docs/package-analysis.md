# Whole-package analysis

Razin analyzes the directory containing each `SKILL.md` without importing or
executing package code. The analyzer is deterministic and bounded. It:

- hashes scanned paths, contents, sizes, and file modes into a versioned SHA-256 coverage digest;
- parses Python helpers with the standard-library AST;
- applies conservative source-to-sink correlations to JavaScript, TypeScript,
  and shell helpers;
- links helper findings to file references in `SKILL.md`;
- checks mutable GitHub/GitLab branch references;
- matches operator-configured known-bad domains, file hashes, and literal IOCs;
- emits explicit analysis gaps for limits, parse failures, symlinks, archives,
  compiled binaries, and unsupported source languages.

Source and sink presence alone is not an attack-chain finding. For example, an
API token used only in an `Authorization` header is not treated as data
exfiltration. `PACKAGE_DATA_EXFILTRATION` requires a correlated sensitive value
in outbound body/data content. `PACKAGE_REMOTE_CODE_EXECUTION` requires remote
content to reach an execution sink, or a declared executable helper that pipes
a download directly to a shell. This is high-priority dangerous behavior, but
does not by itself make a malicious-intent claim.

## Bounds

```yaml
package_analysis:
  enabled: true
  max_files: 256
  max_directories: 128
  max_total_mb: 16
  max_file_mb: 2
  max_findings_per_rule: 20
  emit_inventory: false
```

The defaults prevent a package from forcing unbounded filesystem work or
unbounded output. Reaching a limit produces `INCOMPLETE_SCAN`; it does not make
the package appear fully covered. Archives, binary executables, and unsupported source
languages produce `DYNAMIC_ANALYSIS_REQUIRED`.

`emit_inventory` is off by default so inventory alone does not change a package
from `no-actionable-malicious-evidence` to `capability-only`. API callers can use the package analyzer's deterministic
manifest and versioned coverage digest directly; enabling this setting also emits a
`PACKAGE_INVENTORY` capability finding.

The v3 package-analysis digest binds the bounded static inventory and its
package-level coverage markers. It is not an execution-approval or sandbox
snapshot digest: outer parsing and MCP failures are reported separately in
`coverage_reasons`.

## Known-bad indicators

Razin has no implicit threat-intelligence feed. Configured indicator findings
are only as current and trustworthy as the values you configure:

```yaml
package_analysis:
  known_bad:
    domains:
      - webhook.example
    sha256:
      - "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    indicators:
      - campaign-marker-123
```

Domain matching includes subdomains. Hashes must be full 64-character SHA-256
values. Literal indicators are matched case-insensitively. An exact file-hash
match is treated as a strong IOC; domain and literal matches remain review
signals because context can make them ambiguous. Keep these lists small,
reviewed, and provenance-backed.

## Supported and unsupported content

Python (`.py`), JavaScript/TypeScript (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`,
`.tsx`), and shell (`.sh`, `.bash`, `.zsh`) receive helper behavior analysis.
Recognized source files outside those languages, such as Go, Rust, Ruby, PHP,
Java, Kotlin, Swift, PowerShell, Lua, Perl, and R, are explicitly reported as
requiring additional analysis.

Razin does not follow symlinks, unpack archives, emulate programs, make network
requests, or run package installation hooks.
