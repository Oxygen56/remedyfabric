from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspaceSnapshot:
    files: dict[str, bytes]
    digest: str

    @classmethod
    def capture(cls, workspace: Path) -> WorkspaceSnapshot:
        files: dict[str, bytes] = {}
        digest = hashlib.sha256()
        for path in sorted(workspace.rglob("*")):
            if not path.is_file() or ".git" in path.parts or "evidence" in path.parts:
                continue
            rel = path.relative_to(workspace).as_posix()
            data = path.read_bytes()
            files[rel] = data
            digest.update(rel.encode("utf-8") + b"\0" + data)
        return cls(files=files, digest=digest.hexdigest())

    def restore(self, workspace: Path) -> None:
        current = {
            path.relative_to(workspace).as_posix(): path
            for path in workspace.rglob("*")
            if path.is_file() and ".git" not in path.parts and "evidence" not in path.parts
        }
        for rel, path in current.items():
            if rel not in self.files:
                path.unlink()
        for rel, data in self.files.items():
            path = workspace / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def matches(self, workspace: Path) -> bool:
        return WorkspaceSnapshot.capture(workspace).digest == self.digest
