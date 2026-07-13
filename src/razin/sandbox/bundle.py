"""Race-aware skill snapshotting and canonical archive verification."""

from __future__ import annotations

import io
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path

from razin.constants.sandbox import (
    SANDBOX_MAX_BUNDLE_BYTES,
    SANDBOX_MAX_BUNDLE_FILES,
    SANDBOX_MAX_FILE_BYTES,
)
from razin.exceptions import SandboxValidationError
from razin.sandbox.contract import sha256_hex, validate_relative_path

_READ_SIZE = 1024 * 1024
_MAX_DIRECTORIES = SANDBOX_MAX_BUNDLE_FILES


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    """One sealed regular file in a canonical skill snapshot."""

    path: str
    mode: int
    data: bytes

    @property
    def size_bytes(self) -> int:
        """Return captured byte length."""
        return len(self.data)

    @property
    def sha256(self) -> str:
        """Return captured content digest."""
        return sha256_hex(self.data)

    def manifest_entry(self) -> dict[str, object]:
        """Serialize the stable public manifest entry."""
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "mode": self.mode,
        }


def _stable_stat_tuple(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_flags(*, directory: bool = False) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SandboxValidationError("this platform lacks required secure file-opening primitives")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _read_stable_regular_file(*, parent_fd: int, name: str, expected: os.stat_result, path: str) -> bytes:
    if expected.st_nlink != 1:
        raise SandboxValidationError(f"bundle member {path!r} is hard-linked")
    if expected.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise SandboxValidationError(f"bundle member {path!r} has setuid or setgid bits")
    if expected.st_size > SANDBOX_MAX_FILE_BYTES:
        raise SandboxValidationError(f"bundle member {path!r} exceeds the per-file byte limit")

    try:
        fd = os.open(name, _open_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise SandboxValidationError(f"cannot securely open bundle member {path!r}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or _stable_stat_tuple(before) != _stable_stat_tuple(expected):
            raise SandboxValidationError(f"bundle member {path!r} changed before it was read")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(_READ_SIZE, remaining))
            if not chunk:
                raise SandboxValidationError(f"bundle member {path!r} became shorter while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise SandboxValidationError(f"bundle member {path!r} became longer while it was read")
        after = os.fstat(fd)
        if _stable_stat_tuple(before) != _stable_stat_tuple(after):
            raise SandboxValidationError(f"bundle member {path!r} changed while it was read")
        return b"".join(chunks)
    except OSError as exc:
        raise SandboxValidationError(f"cannot securely read bundle member {path!r}: {exc}") from exc
    finally:
        os.close(fd)


def snapshot_directory(
    root: Path,
    *,
    expected_root_identity: tuple[int, int] | None = None,
) -> tuple[SnapshotFile, ...]:
    """Capture a bounded directory without following aliases or special files."""
    try:
        root_path = Path(os.path.abspath(root))
        root_lstat = root_path.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise SandboxValidationError(f"cannot inspect sandbox root: {exc}") from exc
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise SandboxValidationError("sandbox root must be a real directory, not a symlink")

    try:
        root_fd = os.open(root_path, _open_flags(directory=True))
    except (OSError, ValueError) as exc:
        raise SandboxValidationError(f"cannot securely open sandbox root: {exc}") from exc

    files: list[SnapshotFile] = []
    total_bytes = 0
    directory_count = 0
    root_device = root_lstat.st_dev

    def visit(directory_fd: int, prefix: str) -> None:
        nonlocal total_bytes, directory_count
        directory_count += 1
        if directory_count > _MAX_DIRECTORIES:
            raise SandboxValidationError("sandbox root exceeds the directory-count limit")
        before_directory = os.fstat(directory_fd)
        if before_directory.st_dev != root_device:
            raise SandboxValidationError("sandbox root crosses a filesystem boundary")
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise SandboxValidationError(f"cannot enumerate sandbox directory {prefix or '.'!r}: {exc}") from exc

        for entry in entries:
            try:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                path = validate_relative_path(relative, field="bundle member path")
            except UnicodeEncodeError as exc:
                raise SandboxValidationError("bundle member path is not valid UTF-8") from exc
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SandboxValidationError(f"cannot inspect bundle member {relative!r}: {exc}") from exc
            if entry_stat.st_dev != root_device:
                raise SandboxValidationError(f"bundle member {path!r} crosses a filesystem boundary")
            if stat.S_ISLNK(entry_stat.st_mode):
                raise SandboxValidationError(f"bundle member {path!r} is a symlink")
            if stat.S_ISDIR(entry_stat.st_mode):
                try:
                    child_fd = os.open(entry.name, _open_flags(directory=True), dir_fd=directory_fd)
                except OSError as exc:
                    raise SandboxValidationError(f"cannot securely open bundle directory {path!r}: {exc}") from exc
                try:
                    opened_stat = os.fstat(child_fd)
                    if _stable_stat_tuple(opened_stat) != _stable_stat_tuple(entry_stat):
                        raise SandboxValidationError(f"bundle directory {path!r} changed before traversal")
                    visit(child_fd, path)
                    if _stable_stat_tuple(opened_stat) != _stable_stat_tuple(os.fstat(child_fd)):
                        raise SandboxValidationError(f"bundle directory {path!r} changed during traversal")
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise SandboxValidationError(f"bundle member {path!r} is not a regular file")
            if len(files) >= SANDBOX_MAX_BUNDLE_FILES:
                raise SandboxValidationError("sandbox root exceeds the file-count limit")
            data = _read_stable_regular_file(
                parent_fd=directory_fd,
                name=entry.name,
                expected=entry_stat,
                path=path,
            )
            total_bytes += len(data)
            if total_bytes > SANDBOX_MAX_BUNDLE_BYTES:
                raise SandboxValidationError("sandbox root exceeds the total-byte limit")
            files.append(SnapshotFile(path=path, mode=stat.S_IMODE(entry_stat.st_mode), data=data))

        if _stable_stat_tuple(before_directory) != _stable_stat_tuple(os.fstat(directory_fd)):
            raise SandboxValidationError(f"sandbox directory {prefix or '.'!r} changed during enumeration")

    try:
        opened_root_stat = os.fstat(root_fd)
        if _stable_stat_tuple(opened_root_stat) != _stable_stat_tuple(root_lstat):
            raise SandboxValidationError("sandbox root changed before traversal")
        if expected_root_identity is not None and (opened_root_stat.st_dev, opened_root_stat.st_ino) != (
            expected_root_identity
        ):
            raise SandboxValidationError("sandbox root identity changed before traversal")
        visit(root_fd, "")
    except OSError as exc:
        raise SandboxValidationError(f"sandbox root metadata changed or became unreadable: {exc}") from exc
    finally:
        os.close(root_fd)
    if not files:
        raise SandboxValidationError("sandbox root contains no regular files")
    return tuple(sorted(files, key=lambda item: item.path))


def build_canonical_archive(files: tuple[SnapshotFile, ...]) -> bytes:
    """Build deterministic USTAR bytes from captured regular files."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for item in files:
            validate_relative_path(item.path, field="bundle member path")
            info = tarfile.TarInfo(item.path)
            info.size = len(item.data)
            info.mode = item.mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.type = tarfile.REGTYPE
            archive.addfile(info, io.BytesIO(item.data))
    return output.getvalue()


def verify_canonical_archive(*, archive_bytes: bytes, bundle: dict[str, object]) -> tuple[SnapshotFile, ...]:
    """Verify exact bundle bytes, manifest, and canonical archive encoding."""
    if sha256_hex(archive_bytes) != bundle["sha256"]:
        raise SandboxValidationError("bundle archive SHA-256 does not match the plan")
    if len(archive_bytes) != bundle["archive_bytes"]:
        raise SandboxValidationError("bundle archive byte length does not match the plan")

    parsed: list[SnapshotFile] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            for index, member in enumerate(archive):
                if index >= SANDBOX_MAX_BUNDLE_FILES:
                    raise SandboxValidationError("bundle archive exceeds the file-count limit")
                path = validate_relative_path(member.name, field="bundle archive member path")
                if not member.isreg() or member.islnk() or member.issym():
                    raise SandboxValidationError(f"bundle archive member {path!r} is not a regular file")
                if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
                    raise SandboxValidationError(f"bundle archive member {path!r} has non-canonical metadata")
                if (
                    member.mode < 0
                    or member.mode > 0o777
                    or member.size < 0
                    or member.size > SANDBOX_MAX_FILE_BYTES
                    or member.pax_headers
                ):
                    raise SandboxValidationError(f"bundle archive member {path!r} exceeds the canonical contract")
                handle = archive.extractfile(member)
                if handle is None:
                    raise SandboxValidationError(f"bundle archive member {path!r} cannot be read")
                data = handle.read(SANDBOX_MAX_FILE_BYTES + 1)
                if len(data) != member.size:
                    raise SandboxValidationError(f"bundle archive member {path!r} has an invalid length")
                parsed.append(SnapshotFile(path=path, mode=member.mode, data=data))
    except SandboxValidationError:
        raise
    except (tarfile.TarError, OSError, ValueError, EOFError, OverflowError) as exc:
        raise SandboxValidationError(f"bundle archive is invalid: {exc}") from exc

    parsed_tuple = tuple(parsed)
    if not parsed_tuple or tuple(item.path for item in parsed_tuple) != tuple(
        sorted(item.path for item in parsed_tuple)
    ):
        raise SandboxValidationError("bundle archive members must be non-empty and sorted")
    if len({item.path for item in parsed_tuple}) != len(parsed_tuple):
        raise SandboxValidationError("bundle archive contains duplicate paths")
    if build_canonical_archive(parsed_tuple) != archive_bytes:
        raise SandboxValidationError("bundle archive is not canonical USTAR")
    expected_manifest = [item.manifest_entry() for item in parsed_tuple]
    if expected_manifest != bundle["members"]:
        raise SandboxValidationError("bundle archive contents do not match the plan manifest")
    if sum(item.size_bytes for item in parsed_tuple) != bundle["total_bytes"]:
        raise SandboxValidationError("bundle archive total bytes do not match the plan")
    if len(parsed_tuple) != bundle["file_count"]:
        raise SandboxValidationError("bundle archive file count does not match the plan")
    return parsed_tuple
