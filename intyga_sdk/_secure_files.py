"""Private files for the offline-approval state (mirrors packages/sdk/src/secure-files.ts).

The trust bundle, the redemption markers and the pending-reconciliation records live in one
directory that tools in every SDK language share, so the modes and the exclusive-create discipline
are the same everywhere: directories ``0700``, files ``0600`` where the platform implements POSIX
modes. Private: nothing here is API.
"""

import os
import stat
import uuid
from typing import Union

PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

# O_NOFOLLOW / O_CLOEXEC do not exist on Windows; O_BINARY exists only there (without it the C
# runtime opens in text mode and rewrites "\n" as "\r\n").
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_EXTRA = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)


def _repair_mode(target: str, mode: int) -> None:
    try:
        os.chmod(target, mode)
    except OSError:
        # Windows and some network filesystems do not implement POSIX modes. Creation stays
        # exclusive; the containing volume must be protected there.
        pass


def ensure_private_dir(directory: str) -> None:
    """Create (or repair) a private directory, refusing a symlink or a non-directory in its place."""
    os.makedirs(directory, mode=PRIVATE_DIR_MODE, exist_ok=True)
    st = os.lstat(directory)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OSError(f"refusing unsafe directory: {directory}")
    _repair_mode(directory, PRIVATE_DIR_MODE)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def write_private_file(path: str, contents: Union[str, bytes]) -> None:
    """Atomically replace a sensitive file from a same-directory, exclusively created temporary."""
    directory = os.path.dirname(path) or "."
    ensure_private_dir(directory)
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise OSError(f"refusing unsafe file: {path}")
    data = contents.encode("utf-8") if isinstance(contents, str) else contents
    temp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.{uuid.uuid4()}.tmp")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _EXTRA, PRIVATE_FILE_MODE)
        try:
            _write_all(fd, data)
        finally:
            os.close(fd)
        _repair_mode(temp, PRIVATE_FILE_MODE)
        os.replace(temp, path)
        _repair_mode(path, PRIVATE_FILE_MODE)
    finally:
        try:
            os.unlink(temp)
        except OSError:
            pass


def create_private_marker(path: str, contents: str) -> bool:
    """Create ``path`` exactly once. ``O_EXCL`` makes two racing claims of the same marker impossible
    to both succeed, and ``O_NOFOLLOW`` stops a planted symlink standing in for it. Returns False when
    the marker already exists or cannot be created."""
    ensure_private_dir(os.path.dirname(path) or ".")
    try:
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _EXTRA, PRIVATE_FILE_MODE
        )
    except OSError:
        return False
    try:
        _write_all(fd, contents.encode("utf-8"))
        if hasattr(os, "fchmod"):
            os.fchmod(fd, PRIVATE_FILE_MODE)
    except OSError:
        return False
    finally:
        os.close(fd)
    return True
