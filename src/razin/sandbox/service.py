"""Two-phase sandbox planning, approval, verification, and simulation."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from razin import __version__
from razin.constants.sandbox import (
    SANDBOX_APPROVAL_BINDING_VERSION,
    SANDBOX_ARCHIVE_FORMAT,
    SANDBOX_BUNDLE_DIGEST_VERSION,
    SANDBOX_PLAN_ARTIFACT_TYPE,
    SANDBOX_RESULT_ARTIFACT_TYPE,
    SANDBOX_SCHEMA_VERSION,
    SANDBOX_SIMULATION_ADAPTER_VERSION,
    SANDBOX_SIMULATION_BACKEND,
    sandbox_limits,
    sandbox_policy,
)
from razin.exceptions import SandboxBackendError, SandboxValidationError
from razin.sandbox.backend import BackendOutcome, builtin_backends
from razin.sandbox.bundle import build_canonical_archive, snapshot_directory, verify_canonical_archive
from razin.sandbox.contract import (
    approval_binding_sha256,
    executor_contract_sha256,
    limits_sha256,
    planner_contract_sha256,
    policy_sha256,
    sha256_hex,
    validate_argv,
    validate_image_reference,
    validate_plan,
)
from razin.sandbox.secure_io import (
    ArtifactDestination,
    DirectoryIdentity,
    artifact_names_alias,
    bind_destination,
    destination_aliases_file,
    directory_is_within,
    pin_destination,
    pin_directory,
    secure_read_at,
    validate_artifact_name,
    write_bytes_atomic,
)

_MAX_PLAN_BYTES = 1 * 1024 * 1024


def _json_artifact_bytes(payload: object) -> bytes:
    try:
        return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SandboxValidationError(f"sandbox artifact cannot be encoded as UTF-8 JSON: {exc}") from exc


def _strict_json_loads(data: bytes) -> object:
    def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SandboxValidationError(f"JSON artifact contains duplicate field {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except SandboxValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SandboxValidationError(f"sandbox artifact is not valid strict UTF-8 JSON: {exc}") from exc


def _nearest_existing_directory(path: Path) -> Path:
    try:
        candidate = Path(os.path.abspath(path))
        while not candidate.exists():
            parent = candidate.parent
            if parent == candidate:
                break
            candidate = parent
        return candidate
    except (OSError, RuntimeError, ValueError) as exc:
        raise SandboxValidationError(f"cannot inspect sandbox artifact directory path: {exc}") from exc


def _pin_destination_outside_root(
    *,
    path: Path,
    root_identity: DirectoryIdentity,
) -> ArtifactDestination:
    """Reject source-contained outputs before and after creating parents."""
    nearest = pin_directory(_nearest_existing_directory(path.parent))
    try:
        if directory_is_within(nearest, root_identity):
            raise SandboxValidationError("plan and bundle output directory must be outside the sandbox root")
    finally:
        nearest.close()

    destination = pin_destination(path)
    try:
        if directory_is_within(destination.directory, root_identity):
            raise SandboxValidationError("plan and bundle output directory must be outside the sandbox root")
        return destination
    except Exception:
        destination.directory.close()
        raise


def create_plan(
    *,
    root: Path,
    plan_path: Path,
    argv: list[str],
    backend: str,
    image_reference: str,
) -> dict[str, Any]:
    """Seal a skill package and write an immutable, non-executing plan."""
    if backend != SANDBOX_SIMULATION_BACKEND:
        raise SandboxValidationError("sandbox contract v1 supports only the explicit 'simulated' backend")
    normalized_argv = validate_argv(argv)
    image = validate_image_reference(image_reference)

    root_directory = pin_directory(root, reject_final_symlink=True)
    plan_destination: ArtifactDestination | None = None
    try:
        plan_destination = _pin_destination_outside_root(path=plan_path, root_identity=root_directory.identity)
        files = snapshot_directory(root, expected_root_identity=root_directory.identity)
        if "SKILL.md" not in {item.path for item in files}:
            raise SandboxValidationError("sandbox root must contain a regular top-level SKILL.md")
        archive_bytes = build_canonical_archive(files)
        archive_sha256 = sha256_hex(archive_bytes)
        archive_name = f"sandbox-bundle-{archive_sha256}.tar"
        archive_destination = bind_destination(plan_destination.directory, archive_name)
        if artifact_names_alias(plan_destination.name, archive_destination.name) or (
            plan_destination.existing_identity is not None
            and plan_destination.existing_identity == archive_destination.existing_identity
        ):
            raise SandboxValidationError("plan output must not alias the content-addressed bundle filename")

        members = [item.manifest_entry() for item in files]
        policy = sandbox_policy()
        limits = sandbox_limits()
        plan: dict[str, Any] = {
            "schema_version": SANDBOX_SCHEMA_VERSION,
            "artifact_type": SANDBOX_PLAN_ARTIFACT_TYPE,
            "bundle": {
                "digest_version": SANDBOX_BUNDLE_DIGEST_VERSION,
                "archive_format": SANDBOX_ARCHIVE_FORMAT,
                "archive_file": archive_name,
                "sha256": archive_sha256,
                "archive_bytes": len(archive_bytes),
                "file_count": len(files),
                "total_bytes": sum(item.size_bytes for item in files),
                "members": members,
            },
            "command": {"argv": normalized_argv, "cwd": "."},
            "runtime": {
                "backend": backend,
                "backend_adapter_version": SANDBOX_SIMULATION_ADAPTER_VERSION,
                "image_reference": image,
            },
            "policy": policy,
            "limits": limits,
            "approval": {
                "required": True,
                "method": "exact-binding-sha256",
                "binding_version": SANDBOX_APPROVAL_BINDING_VERSION,
                "binding_sha256": "0" * 64,
            },
            "provenance": {
                "razin_version": __version__,
                "planner_contract_sha256": planner_contract_sha256(),
                "executor_contract_sha256": executor_contract_sha256(),
            },
        }
        plan["approval"]["binding_sha256"] = approval_binding_sha256(plan)
        validate_plan(plan)
        write_bytes_atomic(archive_destination, archive_bytes)
        write_bytes_atomic(plan_destination, _json_artifact_bytes(plan))
        return plan
    finally:
        if plan_destination is not None:
            plan_destination.directory.close()
        root_directory.close()


def _validate_backend_outcome(outcome: BackendOutcome) -> None:
    if outcome != BackendOutcome(
        execution_status="simulated",
        reason_codes=("simulation-only",),
        enforcement_status="not-applied",
        conclusion="not-run",
    ):
        raise SandboxBackendError("the v1 simulation backend returned an unsupported outcome")


def run_plan(
    *,
    plan_path: Path,
    approval_sha256: str,
    result_path: Path,
) -> dict[str, Any]:
    """Verify exact approval and snapshot bytes, then invoke the closed backend."""
    plan_name = validate_artifact_name(plan_path.name, field="plan filename")
    plan_directory = pin_directory(plan_path.parent)
    result_destination: ArtifactDestination | None = None
    try:
        raw_plan, plan_file_identity = secure_read_at(
            plan_directory,
            plan_name,
            maximum_bytes=_MAX_PLAN_BYTES,
        )
        plan = validate_plan(_strict_json_loads(raw_plan))
        expected_approval = plan["approval"]["binding_sha256"]
        if approval_sha256 != expected_approval:
            raise SandboxValidationError("provided approval digest does not match the plan")

        bundle_name = validate_artifact_name(plan["bundle"]["archive_file"], field="bundle filename")
        raw_bundle, bundle_file_identity = secure_read_at(
            plan_directory,
            bundle_name,
            maximum_bytes=plan["bundle"]["archive_bytes"],
            expected_bytes=plan["bundle"]["archive_bytes"],
        )
        verify_canonical_archive(archive_bytes=raw_bundle, bundle=plan["bundle"])

        result_destination = pin_destination(result_path)
        if destination_aliases_file(
            result_destination,
            source_directory=plan_directory,
            source_name=plan_name,
            source_identity=plan_file_identity,
        ) or destination_aliases_file(
            result_destination,
            source_directory=plan_directory,
            source_name=bundle_name,
            source_identity=bundle_file_identity,
        ):
            raise SandboxValidationError("result output must not alias the plan or bundle")

        registry = builtin_backends()
        backend_id = plan["runtime"]["backend"]
        selected = registry.get(backend_id)
        if selected is None:
            raise SandboxBackendError(f"sandbox backend {backend_id!r} is unavailable")
        adapter_version = plan["runtime"]["backend_adapter_version"]
        if selected.backend_id != backend_id or selected.adapter_version != adapter_version:
            raise SandboxBackendError("sandbox backend identity does not match the approved plan")

        approved_bundle_sha256 = plan["bundle"]["sha256"]
        approved_image_reference = plan["runtime"]["image_reference"]
        approved_policy_sha256 = policy_sha256(plan["policy"])
        approved_limits_sha256 = limits_sha256(plan["limits"])
        backend_plan = copy.deepcopy(plan)
        try:
            outcome = selected.run(plan=backend_plan, bundle_bytes=raw_bundle)
        except SandboxBackendError:
            raise
        except Exception as exc:
            raise SandboxBackendError(f"sandbox backend failed: {exc}") from exc
        _validate_backend_outcome(outcome)

        result: dict[str, Any] = {
            "schema_version": SANDBOX_SCHEMA_VERSION,
            "artifact_type": SANDBOX_RESULT_ARTIFACT_TYPE,
            "execution_status": outcome.execution_status,
            "reason_codes": list(outcome.reason_codes),
            "plan": {
                "artifact_sha256": sha256_hex(raw_plan),
                "approval_binding_sha256": expected_approval,
                "bundle_sha256": approved_bundle_sha256,
            },
            "approval": {
                "required": True,
                "status": "matched",
                "provided_binding_sha256": approval_sha256,
            },
            "snapshot": {
                "bundle_sha256": sha256_hex(raw_bundle),
                "matches_plan": True,
            },
            "runtime": {
                "backend": backend_id,
                "backend_adapter_version": adapter_version,
                "image_reference": approved_image_reference,
            },
            "enforcement": {
                "status": outcome.enforcement_status,
                "policy_sha256": approved_policy_sha256,
                "limits_sha256": approved_limits_sha256,
                "backend_invocation_sha256": outcome.backend_invocation_sha256,
            },
            "backend_instance_id": outcome.backend_instance_id,
            "process": outcome.process,
            "conclusion": outcome.conclusion,
        }
        write_bytes_atomic(result_destination, _json_artifact_bytes(result))
        return result
    finally:
        if result_destination is not None:
            result_destination.directory.close()
        plan_directory.close()
