"""Descriptor-pinned I/O for security-sensitive sandbox artifacts."""

from __future__ import annotations

import os
import secrets
import stat
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from razin.exceptions import SandboxValidationError

DirectoryIdentity = tuple[int, int]
FileIdentity = tuple[int, int]

_READ_SIZE = 1024 * 1024
_MAX_ANCESTORS = 2_048
_MAX_ARTIFACT_NAME_BYTES = 240


def _require_secure_primitives() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SandboxValidationError("this platform lacks required secure file-opening primitives")


def _directory_flags() -> int:
    _require_secure_primitives()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    _require_secure_primitives()
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _directory_identity(value: os.stat_result) -> DirectoryIdentity:
    return (value.st_dev, value.st_ino)


def _file_identity(value: os.stat_result) -> FileIdentity:
    return (value.st_dev, value.st_ino)


def _stable_file_stat(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def validate_artifact_name(name: str, *, field: str = "artifact filename") -> str:
    """Validate one portable, normalized directory-entry name."""
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise SandboxValidationError(f"{field} must be a single non-empty filename")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise SandboxValidationError(f"{field} contains a control character")
    if unicodedata.normalize("NFC", name) != name:
        raise SandboxValidationError(f"{field} must use NFC Unicode normalization")
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SandboxValidationError(f"{field} is not valid UTF-8") from exc
    if len(encoded) > _MAX_ARTIFACT_NAME_BYTES:
        raise SandboxValidationError(f"{field} exceeds {_MAX_ARTIFACT_NAME_BYTES} UTF-8 bytes")
    return name


def artifact_names_alias(first: str, second: str) -> bool:
    """Compare portable filename aliases before any filesystem mutation."""
    return unicodedata.normalize("NFC", first).casefold() == unicodedata.normalize("NFC", second).casefold()


@dataclass(slots=True)
class PinnedDirectory:
    """An opened directory whose identity survives pathname replacement."""

    fd: int
    display_path: Path
    identity: DirectoryIdentity

    def close(self) -> None:
        """Close the pinned descriptor."""
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


@dataclass(slots=True)
class ArtifactDestination:
    """A final filename bound to a pinned output directory."""

    directory: PinnedDirectory
    name: str
    existing_identity: FileIdentity | None


def pin_directory(
    path: Path,
    *,
    create: bool = False,
    reject_final_symlink: bool = False,
) -> PinnedDirectory:
    """Open and pin a directory after optional bounded path creation."""
    _require_secure_primitives()
    try:
        absolute = Path(os.path.abspath(path))
        if create:
            absolute.mkdir(parents=True, exist_ok=True)
        if reject_final_symlink and stat.S_ISLNK(absolute.lstat().st_mode):
            raise SandboxValidationError(f"directory {path} must not be a symlink")
        resolved = absolute.resolve(strict=True)
        expected = resolved.lstat()
        if not stat.S_ISDIR(expected.st_mode) or stat.S_ISLNK(expected.st_mode):
            raise SandboxValidationError(f"directory {path} is not a real directory")
        fd = os.open(resolved, _directory_flags())
    except SandboxValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise SandboxValidationError(f"cannot securely open directory {path}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or _directory_identity(opened) != _directory_identity(expected):
            raise SandboxValidationError(f"directory {path} changed while it was opened")
        return PinnedDirectory(fd=fd, display_path=path, identity=_directory_identity(opened))
    except SandboxValidationError:
        os.close(fd)
        raise
    except (OSError, ValueError) as exc:
        os.close(fd)
        raise SandboxValidationError(f"cannot verify opened directory {path}: {exc}") from exc


def directory_is_within(directory: PinnedDirectory, ancestor: DirectoryIdentity) -> bool:
    """Compare directory ancestry by device/inode identity, not path spelling."""
    current_fd: int | None = None
    try:
        current_fd = os.dup(directory.fd)
        for _ in range(_MAX_ANCESTORS):
            current = _directory_identity(os.fstat(current_fd))
            if current == ancestor:
                return True
            parent_fd = os.open("..", _directory_flags(), dir_fd=current_fd)
            try:
                parent = _directory_identity(os.fstat(parent_fd))
            except Exception:
                os.close(parent_fd)
                raise
            if parent == current:
                os.close(parent_fd)
                return False
            os.close(current_fd)
            current_fd = parent_fd
    except (OSError, ValueError) as exc:
        raise SandboxValidationError(f"cannot verify output-directory ancestry: {exc}") from exc
    finally:
        if current_fd is not None:
            os.close(current_fd)
    raise SandboxValidationError("output-directory ancestry exceeds the verification bound")


def _existing_entry_identity(directory: PinnedDirectory, name: str) -> FileIdentity | None:
    try:
        current = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SandboxValidationError(f"cannot inspect artifact destination {name!r}: {exc}") from exc
    if stat.S_ISLNK(current.st_mode):
        raise SandboxValidationError(f"artifact destination {name!r} must not be a symlink")
    if not stat.S_ISREG(current.st_mode):
        raise SandboxValidationError(f"artifact destination {name!r} must be a regular file when it exists")
    return _file_identity(current)


def pin_destination(path: Path) -> ArtifactDestination:
    """Create and pin an artifact parent, then bind its final leaf name."""
    name = validate_artifact_name(path.name)
    directory = pin_directory(path.parent, create=True)
    try:
        return ArtifactDestination(
            directory=directory,
            name=name,
            existing_identity=_existing_entry_identity(directory, name),
        )
    except Exception:
        directory.close()
        raise


def bind_destination(directory: PinnedDirectory, name: str) -> ArtifactDestination:
    """Bind another output leaf in an already-pinned directory."""
    normalized = validate_artifact_name(name)
    return ArtifactDestination(
        directory=directory,
        name=normalized,
        existing_identity=_existing_entry_identity(directory, normalized),
    )


def secure_read_at(
    directory: PinnedDirectory,
    name: str,
    *,
    maximum_bytes: int,
    expected_bytes: int | None = None,
) -> tuple[bytes, FileIdentity]:
    """Read one stable regular file relative to a pinned directory."""
    normalized = validate_artifact_name(name)
    try:
        before_path = os.stat(normalized, dir_fd=directory.fd, follow_symlinks=False)
    except OSError as exc:
        raise SandboxValidationError(f"cannot inspect artifact {normalized!r}: {exc}") from exc
    if not stat.S_ISREG(before_path.st_mode) or stat.S_ISLNK(before_path.st_mode):
        raise SandboxValidationError(f"artifact {normalized!r} must be a regular file, not a symlink")
    if before_path.st_nlink != 1:
        raise SandboxValidationError(f"artifact {normalized!r} must not be hard-linked")
    if before_path.st_size > maximum_bytes:
        raise SandboxValidationError(f"artifact {normalized!r} exceeds its byte limit")
    if expected_bytes is not None and before_path.st_size != expected_bytes:
        raise SandboxValidationError(f"artifact {normalized!r} byte length does not match the plan")
    try:
        fd = os.open(normalized, _file_flags(), dir_fd=directory.fd)
    except OSError as exc:
        raise SandboxValidationError(f"cannot securely open artifact {normalized!r}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or _stable_file_stat(before) != _stable_file_stat(before_path):
            raise SandboxValidationError(f"artifact {normalized!r} changed before it was read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(_READ_SIZE, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise SandboxValidationError(f"artifact {normalized!r} exceeds its byte limit")
        after = os.fstat(fd)
        if _stable_file_stat(after) != _stable_file_stat(before):
            raise SandboxValidationError(f"artifact {normalized!r} changed while it was read")
        data = b"".join(chunks)
        if expected_bytes is not None and len(data) != expected_bytes:
            raise SandboxValidationError(f"artifact {normalized!r} byte length does not match the plan")
        return data, _file_identity(after)
    except OSError as exc:
        raise SandboxValidationError(f"cannot securely read artifact {normalized!r}: {exc}") from exc
    finally:
        os.close(fd)


def destination_aliases_file(
    destination: ArtifactDestination,
    *,
    source_directory: PinnedDirectory,
    source_name: str,
    source_identity: FileIdentity,
) -> bool:
    """Detect existing and portable aliases to a protected source artifact."""
    if destination.existing_identity == source_identity:
        return True
    return destination.directory.identity == source_directory.identity and artifact_names_alias(
        destination.name, source_name
    )


def _destination_is_unchanged(destination: ArtifactDestination) -> bool:
    return _existing_entry_identity(destination.directory, destination.name) == destination.existing_identity


def write_bytes_atomic(destination: ArtifactDestination, content: bytes) -> None:
    """Atomically replace one artifact through its pinned directory descriptor."""
    if not _destination_is_unchanged(destination):
        raise SandboxValidationError(f"artifact destination {destination.name!r} changed after it was pinned")
    temp_name: str | None = None
    temp_fd: int | None = None
    try:
        for _ in range(32):
            candidate = f".razin-{secrets.token_hex(12)}.tmp"
            try:
                temp_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=destination.directory.fd,
                )
            except FileExistsError:
                continue
            temp_name = candidate
            break
        if temp_fd is None or temp_name is None:
            raise SandboxValidationError("cannot allocate a unique sandbox artifact temporary file")
        os.fchmod(temp_fd, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        if not _destination_is_unchanged(destination):
            raise SandboxValidationError(f"artifact destination {destination.name!r} changed before replacement")
        os.replace(
            temp_name,
            destination.name,
            src_dir_fd=destination.directory.fd,
            dst_dir_fd=destination.directory.fd,
        )
        temp_name = None
        os.fsync(destination.directory.fd)
    except SandboxValidationError:
        raise
    except OSError as exc:
        raise SandboxValidationError(f"cannot atomically write artifact {destination.name!r}: {exc}") from exc
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_name is not None:
            with suppress(FileNotFoundError):
                os.unlink(temp_name, dir_fd=destination.directory.fd)
