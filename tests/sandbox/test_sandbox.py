"""Tests for sealed sandbox artifacts and simulation-only backend behavior."""

from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import jsonschema
import pytest

from razin.exceptions import SandboxValidationError
from razin.sandbox.backend import BackendOutcome
from razin.sandbox.bundle import snapshot_directory
from razin.sandbox.contract import approval_binding_sha256, validate_plan, validate_relative_path
from razin.sandbox.secure_io import directory_is_within, pin_destination, pin_directory, write_bytes_atomic
from razin.sandbox.service import create_plan, run_plan

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE = "example.invalid/razin@sha256:" + "a" * 64


def _skill(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: fixture\n---\n\nRuns a helper.\n", encoding="utf-8")
    scripts = root / "scripts"
    scripts.mkdir()
    (scripts / "helper.py").write_text("print('hello')\n", encoding="utf-8")
    return root


def _plan(tmp_path: Path, *, argv: list[str] | None = None) -> tuple[Path, dict[str, Any]]:
    root = _skill(tmp_path / "skill")
    plan_path = tmp_path / "audit" / "plan.json"
    plan = create_plan(
        root=root,
        plan_path=plan_path,
        argv=argv or ["python3", "scripts/helper.py"],
        backend="simulated",
        image_reference=IMAGE,
    )
    return plan_path, plan


def test_plan_and_bundle_are_deterministic_and_private(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    first_path = tmp_path / "audit-a" / "plan.json"
    second_path = tmp_path / "audit-b" / "plan.json"

    first = create_plan(
        root=root,
        plan_path=first_path,
        argv=["python3", "scripts/helper.py"],
        backend="simulated",
        image_reference=IMAGE,
    )
    second = create_plan(
        root=root,
        plan_path=second_path,
        argv=["python3", "scripts/helper.py"],
        backend="simulated",
        image_reference=IMAGE,
    )

    assert first == second
    assert first_path.read_bytes() == second_path.read_bytes()
    first_bundle = first_path.parent / first["bundle"]["archive_file"]
    second_bundle = second_path.parent / second["bundle"]["archive_file"]
    assert first_bundle.read_bytes() == second_bundle.read_bytes()
    assert first["bundle"]["members"] == sorted(first["bundle"]["members"], key=lambda item: item["path"])
    assert stat_mode(first_path) == 0o600
    assert stat_mode(first_bundle) == 0o600


def stat_mode(path: Path) -> int:
    """Return permission bits without following aliases."""
    return path.stat().st_mode & 0o777


@pytest.mark.parametrize(
    ("field", "new_value"),
    [
        (("command", "argv"), ["python3", "other.py"]),
        (("command", "cwd"), "subdir"),
        (("runtime", "image_reference"), "example.invalid/other@sha256:" + "b" * 64),
        (("runtime", "backend"), "other"),
        (("policy", "network"), "host"),
        (("limits", "pids"), 65),
        (("bundle", "sha256"), "c" * 64),
        (("provenance", "planner_contract_sha256"), "d" * 64),
    ],
)
def test_approval_digest_binds_every_execution_surface(
    tmp_path: Path,
    field: tuple[str, str],
    new_value: object,
) -> None:
    _, plan = _plan(tmp_path)
    changed = copy.deepcopy(plan)
    changed[field[0]][field[1]] = new_value

    assert approval_binding_sha256(changed) != plan["approval"]["binding_sha256"]


def test_plan_semantic_validator_rejects_unknown_fields(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)
    plan["unexpected"] = True

    with pytest.raises(SandboxValidationError, match="unknown unexpected"):
        validate_plan(plan)


@pytest.mark.parametrize("field", [("bundle", "digest_version"), ("approval", "binding_version")])
def test_plan_semantic_validator_rejects_boolean_integer_versions(tmp_path: Path, field: tuple[str, str]) -> None:
    _, plan = _plan(tmp_path)
    plan[field[0]][field[1]] = True

    with pytest.raises(SandboxValidationError, match="must be an integer"):
        validate_plan(plan)


def test_plan_requires_top_level_skill_file(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    root.mkdir()
    (root / "helper.py").write_text("pass\n", encoding="utf-8")

    with pytest.raises(SandboxValidationError, match="top-level SKILL.md"):
        create_plan(
            root=root,
            plan_path=tmp_path / "audit" / "plan.json",
            argv=["python3", "helper.py"],
            backend="simulated",
            image_reference=IMAGE,
        )


def test_plan_rejects_output_inside_source(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")

    with pytest.raises(SandboxValidationError, match="outside the sandbox root"):
        create_plan(
            root=root, plan_path=root / "audit" / "plan.json", argv=["true"], backend="simulated", image_reference=IMAGE
        )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_plan_rejects_symlink_member(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    (root / "alias.py").symlink_to(root / "scripts" / "helper.py")

    with pytest.raises(SandboxValidationError, match="is a symlink"):
        create_plan(
            root=root,
            plan_path=tmp_path / "audit" / "plan.json",
            argv=["true"],
            backend="simulated",
            image_reference=IMAGE,
        )


def test_plan_rejects_hardlink_member(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    os.link(root / "scripts" / "helper.py", root / "helper-copy.py")

    with pytest.raises(SandboxValidationError, match="hard-linked"):
        create_plan(
            root=root,
            plan_path=tmp_path / "audit" / "plan.json",
            argv=["true"],
            backend="simulated",
            image_reference=IMAGE,
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_plan_rejects_special_file(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    os.mkfifo(root / "pipe")

    with pytest.raises(SandboxValidationError, match="not a regular file"):
        create_plan(
            root=root,
            plan_path=tmp_path / "audit" / "plan.json",
            argv=["true"],
            backend="simulated",
            image_reference=IMAGE,
        )


class CountingBackend:
    backend_id = "simulated"
    adapter_version = "1.0"

    def __init__(self) -> None:
        self.calls = 0

    def run(self, *, plan: dict[str, Any], bundle_bytes: bytes) -> BackendOutcome:
        self.calls += 1
        assert plan["artifact_type"] == "sandbox-verification-plan"
        assert bundle_bytes
        return BackendOutcome(
            execution_status="simulated",
            reason_codes=("simulation-only",),
            enforcement_status="not-applied",
            conclusion="not-run",
        )


def _run_with_backend(
    *,
    backend: CountingBackend,
    plan_path: Path,
    approval_sha256: str,
    result_path: Path,
) -> dict[str, Any]:
    with patch("razin.sandbox.service.builtin_backends", return_value={"simulated": backend}):
        return run_plan(
            plan_path=plan_path,
            approval_sha256=approval_sha256,
            result_path=result_path,
        )


def test_run_plan_has_no_public_backend_injection_seam() -> None:
    assert "backends" not in inspect.signature(run_plan).parameters


def test_wrong_approval_never_calls_backend(tmp_path: Path) -> None:
    plan_path, _ = _plan(tmp_path)
    backend = CountingBackend()

    with (
        patch("razin.sandbox.service.builtin_backends", return_value={"simulated": backend}),
        pytest.raises(SandboxValidationError, match="approval digest"),
    ):
        run_plan(
            plan_path=plan_path,
            approval_sha256="f" * 64,
            result_path=tmp_path / "result.json",
        )

    assert backend.calls == 0


def test_tampered_bundle_never_calls_backend(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    bundle_path = plan_path.parent / plan["bundle"]["archive_file"]
    bundle = bytearray(bundle_path.read_bytes())
    bundle[600] ^= 1
    bundle_path.write_bytes(bundle)
    backend = CountingBackend()

    with (
        patch("razin.sandbox.service.builtin_backends", return_value={"simulated": backend}),
        pytest.raises(SandboxValidationError, match="SHA-256"),
    ):
        run_plan(
            plan_path=plan_path,
            approval_sha256=plan["approval"]["binding_sha256"],
            result_path=tmp_path / "result.json",
        )

    assert backend.calls == 0


def test_tampered_plan_never_calls_backend(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    plan["command"]["argv"] = ["different"]
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    backend = CountingBackend()

    with (
        patch("razin.sandbox.service.builtin_backends", return_value={"simulated": backend}),
        pytest.raises(SandboxValidationError, match="binding_sha256"),
    ):
        run_plan(
            plan_path=plan_path,
            approval_sha256=plan["approval"]["binding_sha256"],
            result_path=tmp_path / "result.json",
        )

    assert backend.calls == 0


def test_duplicate_json_field_never_calls_backend(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    original = plan_path.read_text(encoding="utf-8")
    plan_path.write_text(original.replace("{\n", '{\n  "schema_version": "1.0",\n', 1), encoding="utf-8")
    backend = CountingBackend()

    with (
        patch("razin.sandbox.service.builtin_backends", return_value={"simulated": backend}),
        pytest.raises(SandboxValidationError, match="duplicate field"),
    ):
        run_plan(
            plan_path=plan_path,
            approval_sha256=plan["approval"]["binding_sha256"],
            result_path=tmp_path / "result.json",
        )

    assert backend.calls == 0


def test_source_changes_after_planning_do_not_change_sealed_snapshot(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    (tmp_path / "skill" / "scripts" / "helper.py").write_text("raise SystemExit(99)\n", encoding="utf-8")
    backend = CountingBackend()

    result = _run_with_backend(
        backend=backend,
        plan_path=plan_path,
        approval_sha256=plan["approval"]["binding_sha256"],
        result_path=tmp_path / "result.json",
    )

    assert backend.calls == 1
    assert result["snapshot"]["bundle_sha256"] == plan["bundle"]["sha256"]


class MutatingBackend(CountingBackend):
    def run(self, *, plan: dict[str, Any], bundle_bytes: bytes) -> BackendOutcome:
        plan["runtime"]["image_reference"] = "attacker.invalid/image@sha256:" + "f" * 64
        plan["policy"]["network"] = "host"
        return super().run(plan=plan, bundle_bytes=bundle_bytes)


def test_backend_receives_copy_and_cannot_change_approved_result(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    backend = MutatingBackend()

    result = _run_with_backend(
        backend=backend,
        plan_path=plan_path,
        approval_sha256=plan["approval"]["binding_sha256"],
        result_path=tmp_path / "result.json",
    )

    assert result["runtime"]["image_reference"] == IMAGE
    assert result["plan"]["approval_binding_sha256"] == plan["approval"]["binding_sha256"]
    assert plan["policy"]["network"] == "none"


def test_plan_filename_cannot_alias_content_addressed_bundle(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    first = create_plan(
        root=root,
        plan_path=tmp_path / "first" / "plan.json",
        argv=["true"],
        backend="simulated",
        image_reference=IMAGE,
    )
    alias_name = first["bundle"]["archive_file"].upper()

    with pytest.raises(SandboxValidationError, match="must not alias"):
        create_plan(
            root=root,
            plan_path=tmp_path / "second" / alias_name,
            argv=["true"],
            backend="simulated",
            image_reference=IMAGE,
        )


def test_result_filename_cannot_case_alias_plan(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    plan_path = tmp_path / "audit" / "Plan.Json"
    plan = create_plan(
        root=root,
        plan_path=plan_path,
        argv=["true"],
        backend="simulated",
        image_reference=IMAGE,
    )
    original_plan = plan_path.read_bytes()

    with pytest.raises(SandboxValidationError, match="must not alias"):
        run_plan(
            plan_path=plan_path,
            approval_sha256=plan["approval"]["binding_sha256"],
            result_path=plan_path.with_name("pLAN.jSON"),
        )
    assert plan_path.read_bytes() == original_plan


def test_output_root_case_alias_is_rejected_on_case_insensitive_filesystem(tmp_path: Path) -> None:
    root = _skill(tmp_path / "MixedRoot")
    alias_root = tmp_path / "mixedroot"
    if not alias_root.exists():
        pytest.skip("filesystem is case-sensitive")

    with pytest.raises(SandboxValidationError, match="outside the sandbox root"):
        create_plan(
            root=root,
            plan_path=alias_root / "audit" / "plan.json",
            argv=["true"],
            backend="simulated",
            image_reference=IMAGE,
        )
    assert not (root / "audit").exists()


def test_non_nfc_result_alias_is_rejected(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    plan_path = tmp_path / "audit" / "plán.json"
    plan = create_plan(
        root=root,
        plan_path=plan_path,
        argv=["true"],
        backend="simulated",
        image_reference=IMAGE,
    )

    with pytest.raises(SandboxValidationError, match="NFC Unicode"):
        run_plan(
            plan_path=plan_path,
            approval_sha256=plan["approval"]["binding_sha256"],
            result_path=plan_path.with_name("pla\u0301n.json"),
        )


@pytest.mark.parametrize(
    "malformed",
    [
        "[" * 2_000 + "]" * 2_000,
        '{"value": ' + "9" * 5_000 + "}",
    ],
)
def test_malformed_json_is_normalized_to_validation_error(tmp_path: Path, malformed: str) -> None:
    plan_path, _ = _plan(tmp_path)
    plan_path.write_text(malformed, encoding="utf-8")

    with pytest.raises(SandboxValidationError, match="strict UTF-8 JSON"):
        run_plan(plan_path=plan_path, approval_sha256="a" * 64, result_path=tmp_path / "result.json")


def test_surrogate_json_and_archive_paths_fail_closed(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    raw = plan_path.read_text(encoding="utf-8")
    raw = raw.replace(
        f'"razin_version": "{plan["provenance"]["razin_version"]}"',
        '"razin_version": "\\ud800"',
    )
    plan_path.write_text(raw, encoding="utf-8")

    with pytest.raises(SandboxValidationError, match="canonical UTF-8 JSON"):
        run_plan(
            plan_path=plan_path,
            approval_sha256=plan["approval"]["binding_sha256"],
            result_path=tmp_path / "result.json",
        )
    with pytest.raises(SandboxValidationError, match="not valid UTF-8"):
        validate_relative_path("bad\udcff")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_pinned_output_directory_defeats_parent_swap(tmp_path: Path) -> None:
    original_parent = tmp_path / "output"
    protected_parent = tmp_path / "protected"
    protected_parent.mkdir()
    destination = pin_destination(original_parent / "artifact.json")
    moved_parent = tmp_path / "moved-output"
    original_parent.rename(moved_parent)
    original_parent.symlink_to(protected_parent, target_is_directory=True)
    try:
        write_bytes_atomic(destination, b"sealed\n")
    finally:
        destination.directory.close()

    assert (moved_parent / "artifact.json").read_bytes() == b"sealed\n"
    assert not (protected_parent / "artifact.json").exists()


def test_destination_entry_change_after_pinning_fails_closed(tmp_path: Path) -> None:
    destination_path = tmp_path / "output" / "artifact.json"
    destination = pin_destination(destination_path)
    destination_path.write_text("attacker\n", encoding="utf-8")
    try:
        with pytest.raises(SandboxValidationError, match="changed after it was pinned"):
            write_bytes_atomic(destination, b"sealed\n")
    finally:
        destination.directory.close()

    assert destination_path.read_text(encoding="utf-8") == "attacker\n"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_symlink_loop_in_plan_parent_fails_closed(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second, target_is_directory=True)
    second.symlink_to(first, target_is_directory=True)

    with pytest.raises(SandboxValidationError, match="securely open directory"):
        run_plan(
            plan_path=first / "plan.json",
            approval_sha256="a" * 64,
            result_path=tmp_path / "result.json",
        )


@pytest.mark.parametrize("bad_parent", ["nul\0parent", "surrogate\ud800parent"])
def test_invalid_plan_parent_encoding_fails_closed(tmp_path: Path, bad_parent: str) -> None:
    with pytest.raises(SandboxValidationError, match="securely open directory"):
        run_plan(
            plan_path=tmp_path / bad_parent / "plan.json",
            approval_sha256="a" * 64,
            result_path=tmp_path / "result.json",
        )


def test_directory_metadata_failures_are_normalized(tmp_path: Path) -> None:
    with (
        patch("razin.sandbox.secure_io.os.fstat", side_effect=OSError("injected metadata failure")),
        pytest.raises(SandboxValidationError, match="verify opened directory"),
    ):
        pin_directory(tmp_path)


def test_directory_dup_failure_is_normalized(tmp_path: Path) -> None:
    directory = pin_directory(tmp_path)
    try:
        with (
            patch("razin.sandbox.secure_io.os.dup", side_effect=OSError("injected dup failure")),
            pytest.raises(SandboxValidationError, match="ancestry"),
        ):
            directory_is_within(directory, directory.identity)
    finally:
        directory.close()


def test_snapshot_metadata_failure_is_normalized(tmp_path: Path) -> None:
    root = _skill(tmp_path / "skill")
    with (
        patch("razin.sandbox.bundle.os.fstat", side_effect=OSError("injected snapshot failure")),
        pytest.raises(SandboxValidationError, match="metadata changed or became unreadable"),
    ):
        snapshot_directory(root)


def test_simulation_result_is_explicit_and_schema_valid(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    plan_path, plan = _plan(tmp_path, argv=["touch", str(sentinel)])
    result_path = tmp_path / "result.json"

    result = run_plan(
        plan_path=plan_path,
        approval_sha256=plan["approval"]["binding_sha256"],
        result_path=result_path,
    )

    assert result["execution_status"] == "simulated"
    assert result["reason_codes"] == ["simulation-only"]
    assert result["process"] is None
    assert result["conclusion"] == "not-run"
    assert result["enforcement"]["status"] == "not-applied"
    assert not sentinel.exists()
    assert stat_mode(result_path) == 0o600
    schema = json.loads((REPO_ROOT / "schemas/v1/sandbox_verification_result.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(result, schema)


@pytest.mark.parametrize("name", ["sandbox_verification_plan.schema.json", "sandbox_verification_result.schema.json"])
def test_root_schema_matches_immutable_v1(name: str) -> None:
    latest = json.loads((REPO_ROOT / "schemas" / name).read_text(encoding="utf-8"))
    versioned = json.loads((REPO_ROOT / "schemas/v1" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(latest)
    jsonschema.Draft202012Validator.check_schema(versioned)
    latest["$id"] = versioned["$id"]

    assert latest == versioned


def test_plan_validates_against_public_schema(tmp_path: Path) -> None:
    _, plan = _plan(tmp_path)
    schema = json.loads((REPO_ROOT / "schemas/v1/sandbox_verification_plan.schema.json").read_text(encoding="utf-8"))

    jsonschema.validate(plan, schema)
