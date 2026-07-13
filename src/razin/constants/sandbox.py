"""Immutable defaults for sandbox verification artifacts."""

from __future__ import annotations

SANDBOX_SCHEMA_VERSION = "1.0"
SANDBOX_PLAN_ARTIFACT_TYPE = "sandbox-verification-plan"
SANDBOX_RESULT_ARTIFACT_TYPE = "sandbox-verification-result"
SANDBOX_BUNDLE_DIGEST_VERSION = 1
SANDBOX_APPROVAL_BINDING_VERSION = 1
SANDBOX_ARCHIVE_FORMAT = "ustar-v1"
SANDBOX_SIMULATION_BACKEND = "simulated"
SANDBOX_SIMULATION_ADAPTER_VERSION = "1.0"

SANDBOX_MAX_BUNDLE_FILES = 1_024
SANDBOX_MAX_BUNDLE_BYTES = 64 * 1024 * 1024
SANDBOX_MAX_FILE_BYTES = 16 * 1024 * 1024
SANDBOX_MAX_ARGV_ITEMS = 128
SANDBOX_MAX_ARG_BYTES = 4_096
SANDBOX_MAX_ARGV_BYTES = 32_768
SANDBOX_MAX_RELATIVE_PATH_BYTES = 100


def sandbox_policy() -> dict[str, object]:
    """Return a fresh copy of the immutable v1 isolation policy."""
    return {
        "policy_version": "1.0",
        "network": "none",
        "read_only_rootfs": True,
        "bundle_mount_target": "/workspace",
        "bundle_mount_mode": "read-only",
        "tmpfs_target": "/tmp",
        "inherit_environment": False,
        "environment": {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TMPDIR": "/tmp",
            "TZ": "UTC",
        },
        "stdin": "closed",
        "tty": False,
        "uid": 65_534,
        "gid": 65_534,
        "privileged": False,
        "capabilities": [],
        "no_new_privileges": True,
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "host_mounts": [],
        "devices": [],
    }


def sandbox_limits() -> dict[str, int]:
    """Return a fresh copy of the immutable v1 resource limits."""
    return {
        "bundle_files": SANDBOX_MAX_BUNDLE_FILES,
        "bundle_bytes": SANDBOX_MAX_BUNDLE_BYTES,
        "file_bytes": SANDBOX_MAX_FILE_BYTES,
        "wall_time_seconds": 30,
        "cpu_time_seconds": 10,
        "cpu_millis": 1_000,
        "memory_bytes": 256 * 1024 * 1024,
        "pids": 64,
        "open_files": 256,
        "tmpfs_bytes": 64 * 1024 * 1024,
        "stdout_bytes": 1 * 1024 * 1024,
        "stderr_bytes": 1 * 1024 * 1024,
    }
