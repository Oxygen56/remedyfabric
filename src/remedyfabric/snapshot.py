from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


def _workspace_root(workspace: Path) -> Path:
    if workspace.is_symlink():
        raise RuntimeError("workspace root must not be a symlink")
    root = workspace.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("workspace root must be a directory")
    return root


def _entries(root: Path) -> list[tuple[Path, str]]:
    """Walk without following symlinked directories or special files."""

    discovered: list[tuple[Path, str]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                path = Path(entry.path)
                relative = path.relative_to(root)
                if ".git" in relative.parts:
                    continue
                if entry.is_symlink():
                    discovered.append((path, "symlink"))
                elif entry.is_dir(follow_symlinks=False):
                    discovered.append((path, "directory"))
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    discovered.append((path, "file"))
                else:
                    discovered.append((path, "special"))
    return sorted(discovered, key=lambda item: item[0].relative_to(root).as_posix())


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".remedyfabric-restore-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


@dataclass(frozen=True)
class WorkspaceSnapshot:
    files: dict[str, bytes]
    modes: dict[str, int]
    digest: str

    @classmethod
    def capture(cls, workspace: Path) -> WorkspaceSnapshot:
        root = _workspace_root(workspace)
        files: dict[str, bytes] = {}
        modes: dict[str, int] = {}
        digest = hashlib.sha256()
        for path, kind in _entries(root):
            relative = path.relative_to(root).as_posix()
            if kind == "symlink":
                raise RuntimeError(f"workspace snapshot refuses symlink: {relative}")
            if kind == "special":
                raise RuntimeError(f"workspace snapshot refuses special file: {relative}")
            if kind != "file":
                continue
            data = path.read_bytes()
            mode = path.lstat().st_mode & 0o7777
            files[relative] = data
            modes[relative] = mode
            digest.update(relative.encode("utf-8") + b"\0")
            digest.update(mode.to_bytes(4, "big"))
            digest.update(data)
        return cls(files=files, modes=modes, digest=digest.hexdigest())

    def restore(self, workspace: Path) -> None:
        root = _workspace_root(workspace)
        entries = _entries(root)

        # Remove links without following them.  This must happen before parent
        # creation so restoration can never write through an injected link.
        for path, kind in reversed(entries):
            if kind == "symlink":
                path.unlink()
            elif kind == "special":
                raise RuntimeError(
                    "workspace restore refuses special file: " + path.relative_to(root).as_posix()
                )

        current_files = {
            path.relative_to(root).as_posix(): path
            for path, kind in _entries(root)
            if kind == "file"
        }
        for relative, path in current_files.items():
            if relative not in self.files:
                path.unlink()

        for relative, data in self.files.items():
            path = root.joinpath(*relative.split("/"))
            cursor = root
            for part in relative.split("/")[:-1]:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise RuntimeError(f"snapshot restore refuses symlink parent: {relative}")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise RuntimeError(f"snapshot restore refuses symlink target: {relative}")
            _atomic_write(path, data, self.modes[relative])

        # Empty directories are outside the byte snapshot, but remove newly
        # introduced ones when possible so failed transactions leave less state.
        for path, kind in reversed(_entries(root)):
            if kind == "directory":
                try:
                    path.rmdir()
                except OSError:
                    pass

    def matches(self, workspace: Path) -> bool:
        return WorkspaceSnapshot.capture(workspace).digest == self.digest
