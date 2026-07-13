# Sandbox verification artifacts

Razin can seal one skill package into a deterministic archive, bind an exact
intended command and isolation policy to an operator approval digest, and emit a
simulation result. This workflow is separate from `razin scan` and from
`razin.yaml`.

**Warning:** The v1 backend is simulation-only. It does not start a process,
container, VM, shell, or network connection. It provides no runtime isolation
or dynamic evidence, and it does not decide whether a skill is safe or
malicious.

## Create a plan

The skill root must contain a regular top-level `SKILL.md`. Write the artifacts
outside that root:

```bash
razin sandbox plan \
  --root ./skill \
  --plan-out ./audit/plan.json \
  --backend simulated \
  --image example.invalid/razin@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  -- python3 scripts/helper.py --mode audit
```

Planning writes:

- `plan.json`, which contains the exact argv array, intended pinned image,
  fixed policy and limits, bundle manifest, contract provenance, and approval
  binding;
- `sandbox-bundle-<sha256>.tar`, a deterministic USTAR snapshot containing the
  approved regular files.

Planning does not inspect, pull, or run the image or command. The image value is
recorded only so a future execution adapter cannot change it without requiring
a new approval.

## Approve and simulate

Copy the exact approval digest printed by `sandbox plan`:

```bash
razin sandbox run \
  --plan ./audit/plan.json \
  --approve-plan-sha256 <approval-digest> \
  --result-out ./audit/result.json
```

`sandbox run` validates the plan, compares the explicit approval, securely
reads the content-addressed archive, recomputes its digest and manifest, and
checks that it is canonical. Only then does it invoke the closed backend
registry. The only v1 backend returns `execution_status: simulated`,
`reason_codes: [simulation-only]`, `process: null`, and `conclusion: not-run`.

Changing source files after planning does not change the sealed archive. To
approve new source, create a new plan. Changing any approval-bound field or the
archive invalidates the existing approval or bundle digest. Byte-only JSON
formatting changes keep the semantic approval but are recorded by the result's
exact plan-artifact SHA-256.

## What the approval binds

The domain-separated approval SHA-256 binds all execution-relevant plan fields:

- canonical archive bytes and the complete file manifest;
- exact argv tokens and working directory;
- backend identity, adapter version, and pinned intended image;
- fixed no-network, read-only, non-root policy;
- fixed resource and output limits;
- planner and executor contract provenance.

The digest does not reuse `package_analysis_digest`. That static-analysis digest
has different coverage semantics and is not an execution snapshot.

## Snapshot safety checks

Planning is bounded to 1,024 files, 64 MiB total, and 16 MiB per file. It rejects:

- symlinks, hardlinks, FIFOs, sockets, devices, and non-regular members;
- setuid or setgid files and filesystem-boundary crossings;
- absolute, traversing, non-normalized, case-colliding, or oversized paths;
- files or directories that change while they are read;
- plan and bundle output paths inside the source package.

Artifacts are written atomically with mode `0600`. Runs reject symlinked or
hard-linked plan and bundle files and pass the exact verified archive bytes to
the backend boundary. Artifact directories are pinned by descriptor before
backend dispatch, so path spelling aliases and later parent-path replacement do
not redirect writes. The workflow never rereads or mounts the mutable source
tree.

This optional workflow requires POSIX descriptor-relative file operations,
`O_NOFOLLOW`, and `O_DIRECTORY`. It fails closed on platforms that do not expose
those primitives; ordinary static scans remain available there.

## Policy is intent, not enforcement in v1

The plan records controls required of a future execution adapter, including no
network, a read-only root filesystem and bundle, a non-root UID/GID, no inherited
environment, no capabilities, no new privileges, no host namespaces, no host
mounts or devices, closed stdin, no TTY, and bounded CPU, memory, processes,
temporary storage, time, and output.

Because the simulation backend starts nothing, the result reports
`enforcement.status: not-applied`. A real adapter must be added and reviewed
separately; unsupported controls must fail closed rather than be downgraded.

## Schemas and independence

The public schemas are:

- `schemas/v1/sandbox_verification_plan.schema.json`
- `schemas/v1/sandbox_verification_result.schema.json`

Latest aliases live directly under `schemas/`. Runtime validation is implemented
in the installed Python package because repository-root schema files are not
included in the wheel.

Sandbox artifacts never modify scan findings, evidence verdicts, coverage,
purpose alignment, review priority, classifier features, or CI gates.
