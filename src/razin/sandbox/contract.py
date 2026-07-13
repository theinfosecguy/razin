"""Canonical sandbox artifact contracts and semantic validation."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any

from razin.constants.sandbox import (
    SANDBOX_APPROVAL_BINDING_VERSION,
    SANDBOX_ARCHIVE_FORMAT,
    SANDBOX_BUNDLE_DIGEST_VERSION,
    SANDBOX_MAX_ARG_BYTES,
    SANDBOX_MAX_ARGV_BYTES,
    SANDBOX_MAX_ARGV_ITEMS,
    SANDBOX_MAX_RELATIVE_PATH_BYTES,
    SANDBOX_PLAN_ARTIFACT_TYPE,
    SANDBOX_SCHEMA_VERSION,
    SANDBOX_SIMULATION_ADAPTER_VERSION,
    SANDBOX_SIMULATION_BACKEND,
    sandbox_limits,
    sandbox_policy,
)
from razin.exceptions import SandboxValidationError

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}@sha256:[0-9a-f]{64}$")


def _planner_contract() -> dict[str, object]:
    return {
        "contract": "razin-sandbox-planner",
        "version": 1,
        "archive_format": SANDBOX_ARCHIVE_FORMAT,
        "snapshot": {
            "regular_files_only": True,
            "reject_symlinks": True,
            "reject_special_files": True,
            "reject_hardlinks": True,
            "reject_cross_device": True,
            "reject_setid": True,
            "stable_pre_post_stat": True,
            "canonical_uid_gid_mtime": True,
            "descriptor_pinned_outputs": True,
            "filesystem_identity_ancestry": True,
            "portable_alias_rejection": True,
        },
        "limits": sandbox_limits(),
    }


def _executor_contract() -> dict[str, object]:
    return {
        "contract": "razin-sandbox-executor",
        "version": 1,
        "approval_before_backend": True,
        "verify_canonical_archive": True,
        "descriptor_pinned_inputs_outputs": True,
        "closed_backend_registry": True,
        "backend_receives_plan_copy": True,
        "backend": SANDBOX_SIMULATION_BACKEND,
        "adapter_version": SANDBOX_SIMULATION_ADAPTER_VERSION,
        "simulation_starts_processes": False,
        "policy": sandbox_policy(),
        "limits": sandbox_limits(),
    }


def canonical_json_bytes(value: object) -> bytes:
    """Serialize JSON deterministically for domain-separated hashes."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SandboxValidationError(f"sandbox artifact cannot be encoded as canonical UTF-8 JSON: {exc}") from exc


def sha256_hex(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def domain_hash(domain: str, value: object) -> str:
    """Hash a canonical JSON value in an explicit domain."""
    return sha256_hex(domain.encode("ascii") + b"\0" + canonical_json_bytes(value))


def planner_contract_sha256() -> str:
    """Return the current immutable planner contract digest."""
    return domain_hash("razin-sandbox-planner-contract-v1", _planner_contract())


def executor_contract_sha256() -> str:
    """Return the current immutable executor contract digest."""
    return domain_hash("razin-sandbox-executor-contract-v1", _executor_contract())


def policy_sha256(policy: object) -> str:
    """Hash the exact policy bound by a plan."""
    return domain_hash("razin-sandbox-policy-v1", policy)


def limits_sha256(limits: object) -> str:
    """Hash the exact resource limits bound by a plan."""
    return domain_hash("razin-sandbox-limits-v1", limits)


def validate_relative_path(path: object, *, field: str = "path") -> str:
    """Validate a bounded normalized relative POSIX path."""
    if not isinstance(path, str) or not path:
        raise SandboxValidationError(f"{field} must be a non-empty string")
    try:
        encoded_path = path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SandboxValidationError(f"{field} is not valid UTF-8") from exc
    if len(encoded_path) > SANDBOX_MAX_RELATIVE_PATH_BYTES:
        raise SandboxValidationError(f"{field} exceeds {SANDBOX_MAX_RELATIVE_PATH_BYTES} UTF-8 bytes")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise SandboxValidationError(f"{field} contains a control character")
    if unicodedata.normalize("NFC", path) != path:
        raise SandboxValidationError(f"{field} must use NFC Unicode normalization")
    pure = PurePosixPath(path)
    if pure.is_absolute() or path.startswith("/"):
        raise SandboxValidationError(f"{field} must be relative")
    if path.endswith("/") or "//" in path or "\\" in path:
        raise SandboxValidationError(f"{field} is not normalized POSIX syntax")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise SandboxValidationError(f"{field} is not a normalized contained path")
    if pure.as_posix() != path:
        raise SandboxValidationError(f"{field} is not normalized POSIX syntax")
    return path


def validate_argv(argv: object) -> list[str]:
    """Validate exact argv tokens without interpreting a shell string."""
    if not isinstance(argv, list) or not argv:
        raise SandboxValidationError("command.argv must be a non-empty array")
    if len(argv) > SANDBOX_MAX_ARGV_ITEMS:
        raise SandboxValidationError(f"command.argv exceeds {SANDBOX_MAX_ARGV_ITEMS} items")
    normalized: list[str] = []
    total_bytes = 0
    for index, item in enumerate(argv):
        if not isinstance(item, str) or not item:
            raise SandboxValidationError(f"command.argv[{index}] must be a non-empty string")
        try:
            raw = item.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SandboxValidationError(f"command.argv[{index}] is not valid UTF-8") from exc
        if len(raw) > SANDBOX_MAX_ARG_BYTES:
            raise SandboxValidationError(f"command.argv[{index}] exceeds {SANDBOX_MAX_ARG_BYTES} UTF-8 bytes")
        if any(ord(char) == 0 or ord(char) < 9 or 13 < ord(char) < 32 or ord(char) == 127 for char in item):
            raise SandboxValidationError(f"command.argv[{index}] contains a forbidden control character")
        normalized.append(item)
        total_bytes += len(raw)
    if total_bytes > SANDBOX_MAX_ARGV_BYTES:
        raise SandboxValidationError(f"command.argv exceeds {SANDBOX_MAX_ARGV_BYTES} total UTF-8 bytes")
    return normalized


def validate_image_reference(value: object) -> str:
    """Require an immutable OCI-style sha256 image reference."""
    if not isinstance(value, str) or not _IMAGE_RE.fullmatch(value):
        raise SandboxValidationError("runtime.image_reference must be pinned as name@sha256:<64 lowercase hex>")
    return value


def _require_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SandboxValidationError(f"{field} must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise SandboxValidationError(f"{field} has invalid fields: {'; '.join(details)}")


def _require_int(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SandboxValidationError(f"{field} must be an integer >= {minimum}")
    return value


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SandboxValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def approval_binding_payload(plan: dict[str, Any]) -> dict[str, object]:
    """Return every execution-relevant plan field, excluding the self digest."""
    approval = _require_object(plan.get("approval"), "approval")
    return {
        "binding_version": approval.get("binding_version"),
        "schema_version": plan.get("schema_version"),
        "artifact_type": plan.get("artifact_type"),
        "bundle": plan.get("bundle"),
        "command": plan.get("command"),
        "runtime": plan.get("runtime"),
        "policy": plan.get("policy"),
        "limits": plan.get("limits"),
        "provenance": plan.get("provenance"),
        "approval_required": approval.get("required"),
        "approval_method": approval.get("method"),
    }


def approval_binding_sha256(plan: dict[str, Any]) -> str:
    """Compute the exact operator-approval binding for a plan."""
    return domain_hash("razin-sandbox-approval-v1", approval_binding_payload(plan))


def validate_plan(value: object) -> dict[str, Any]:
    """Validate schema-level and cross-field sandbox plan invariants."""
    plan = _require_object(value, "plan")
    _require_exact_keys(
        plan,
        {
            "schema_version",
            "artifact_type",
            "bundle",
            "command",
            "runtime",
            "policy",
            "limits",
            "approval",
            "provenance",
        },
        "plan",
    )
    if plan["schema_version"] != SANDBOX_SCHEMA_VERSION:
        raise SandboxValidationError("plan schema_version is unsupported")
    if plan["artifact_type"] != SANDBOX_PLAN_ARTIFACT_TYPE:
        raise SandboxValidationError("plan artifact_type is unsupported")

    bundle = _require_object(plan["bundle"], "bundle")
    _require_exact_keys(
        bundle,
        {
            "digest_version",
            "archive_format",
            "archive_file",
            "sha256",
            "archive_bytes",
            "file_count",
            "total_bytes",
            "members",
        },
        "bundle",
    )
    if _require_int(bundle["digest_version"], "bundle.digest_version", minimum=1) != SANDBOX_BUNDLE_DIGEST_VERSION:
        raise SandboxValidationError("bundle.digest_version is unsupported")
    if bundle["archive_format"] != SANDBOX_ARCHIVE_FORMAT:
        raise SandboxValidationError("bundle.archive_format is unsupported")
    archive_sha = _require_sha256(bundle["sha256"], "bundle.sha256")
    expected_archive_file = f"sandbox-bundle-{archive_sha}.tar"
    if bundle["archive_file"] != expected_archive_file:
        raise SandboxValidationError("bundle.archive_file is not derived from bundle.sha256")
    _require_int(bundle["archive_bytes"], "bundle.archive_bytes", minimum=1)
    file_count = _require_int(bundle["file_count"], "bundle.file_count", minimum=1)
    total_bytes = _require_int(bundle["total_bytes"], "bundle.total_bytes")
    members = bundle["members"]
    if not isinstance(members, list) or not members:
        raise SandboxValidationError("bundle.members must be a non-empty array")
    expected_limits = sandbox_limits()
    if len(members) != file_count or file_count > expected_limits["bundle_files"]:
        raise SandboxValidationError("bundle.file_count does not match bounded members")
    member_paths: list[str] = []
    member_total = 0
    for index, raw_member in enumerate(members):
        member = _require_object(raw_member, f"bundle.members[{index}]")
        _require_exact_keys(member, {"path", "size_bytes", "sha256", "mode"}, f"bundle.members[{index}]")
        member_paths.append(validate_relative_path(member["path"], field=f"bundle.members[{index}].path"))
        size = _require_int(member["size_bytes"], f"bundle.members[{index}].size_bytes")
        if size > expected_limits["file_bytes"]:
            raise SandboxValidationError(f"bundle.members[{index}].size_bytes exceeds the file limit")
        member_total += size
        _require_sha256(member["sha256"], f"bundle.members[{index}].sha256")
        mode = _require_int(member["mode"], f"bundle.members[{index}].mode")
        if mode > 0o777:
            raise SandboxValidationError(f"bundle.members[{index}].mode contains unsupported bits")
    if member_paths != sorted(member_paths) or len(member_paths) != len(set(member_paths)):
        raise SandboxValidationError("bundle members must be sorted and path-unique")
    if len({path.casefold() for path in member_paths}) != len(member_paths):
        raise SandboxValidationError("bundle member paths collide on case-insensitive filesystems")
    if total_bytes != member_total or total_bytes > expected_limits["bundle_bytes"]:
        raise SandboxValidationError("bundle.total_bytes does not match bounded members")
    maximum_archive_bytes = total_bytes + file_count * 1_024 + 10_240
    if bundle["archive_bytes"] > maximum_archive_bytes:
        raise SandboxValidationError("bundle.archive_bytes exceeds canonical USTAR bounds")

    command = _require_object(plan["command"], "command")
    _require_exact_keys(command, {"argv", "cwd"}, "command")
    validate_argv(command["argv"])
    if command["cwd"] != ".":
        raise SandboxValidationError("command.cwd must be '.' in sandbox contract v1")

    runtime = _require_object(plan["runtime"], "runtime")
    _require_exact_keys(runtime, {"backend", "backend_adapter_version", "image_reference"}, "runtime")
    if runtime["backend"] != SANDBOX_SIMULATION_BACKEND:
        raise SandboxValidationError("only the explicit simulated backend is supported in sandbox contract v1")
    if runtime["backend_adapter_version"] != SANDBOX_SIMULATION_ADAPTER_VERSION:
        raise SandboxValidationError("runtime.backend_adapter_version is unsupported")
    validate_image_reference(runtime["image_reference"])

    if plan["policy"] != sandbox_policy():
        raise SandboxValidationError("plan policy does not match the immutable sandbox contract")
    if plan["limits"] != expected_limits:
        raise SandboxValidationError("plan limits do not match the immutable sandbox contract")

    approval = _require_object(plan["approval"], "approval")
    _require_exact_keys(approval, {"required", "method", "binding_version", "binding_sha256"}, "approval")
    if approval["required"] is not True or approval["method"] != "exact-binding-sha256":
        raise SandboxValidationError("plan requires exact digest approval")
    if (
        _require_int(approval["binding_version"], "approval.binding_version", minimum=1)
        != SANDBOX_APPROVAL_BINDING_VERSION
    ):
        raise SandboxValidationError("approval.binding_version is unsupported")
    embedded_binding = _require_sha256(approval["binding_sha256"], "approval.binding_sha256")

    provenance = _require_object(plan["provenance"], "provenance")
    _require_exact_keys(
        provenance, {"razin_version", "planner_contract_sha256", "executor_contract_sha256"}, "provenance"
    )
    if not isinstance(provenance["razin_version"], str) or not provenance["razin_version"]:
        raise SandboxValidationError("provenance.razin_version must be a non-empty string")
    if provenance["planner_contract_sha256"] != planner_contract_sha256():
        raise SandboxValidationError("planner contract digest is not supported by this Razin version")
    if provenance["executor_contract_sha256"] != executor_contract_sha256():
        raise SandboxValidationError("executor contract digest is not supported by this Razin version")
    if embedded_binding != approval_binding_sha256(plan):
        raise SandboxValidationError("approval.binding_sha256 does not match the plan")
    return plan
