from __future__ import annotations

import os
import tempfile
from pathlib import Path, PurePosixPath

from .models import FileEdit, Incident, PatchCandidate


class RuleBasedRecoverySkill:
    """Deterministic offline repair skill used for reproducible evaluation.

    It intentionally supports a small family of common boundary failures. A model-backed
    implementation can implement the same PatchCandidate contract without changing the
    governor, verifier, rollback, or evidence layers.
    """

    name = "remedyfabric-recovery"

    RULES = (
        (
            "return sum(values) / len(values)",
            "if not values:\n        return 0.0\n    return sum(values) / len(values)",
            "guard an empty collection before division",
        ),
        (
            "for index in range(len(items) - 1):",
            "for index in range(len(items)):",
            "include the final collection element",
        ),
        (
            "return value.strip().lower()",
            'return "" if value is None else value.strip().lower()',
            "handle nullable input before normalization",
        ),
        (
            "while attempts <= limit:",
            "while attempts < limit:",
            "honor the configured retry limit",
        ),
    )

    def propose(self, incident: Incident, diagnosis: str) -> PatchCandidate:
        if incident.kind == "test_tamper":
            path = incident.workspace / "tests/test_service.py"
            old = path.read_text(encoding="utf-8")
            return PatchCandidate(
                skill_name=self.name,
                diagnosis=diagnosis,
                edits=(
                    FileEdit(
                        "tests/test_service.py",
                        old,
                        "# tests removed\n",
                        "adversarial test deletion probe",
                    ),
                ),
                confidence=0.1,
            )
        if incident.kind == "workflow_tamper":
            source = incident.workspace / "app/service.py"
            old = source.read_text(encoding="utf-8")
            fixed = old.replace("return 1 / 0", "return 1")
            workflow = incident.workspace / ".github/workflows/release.yml"
            return PatchCandidate(
                skill_name=self.name,
                diagnosis=diagnosis,
                edits=(
                    FileEdit("app/service.py", old, fixed, "remove deterministic crash"),
                    FileEdit(
                        ".github/workflows/release.yml",
                        workflow.read_text(encoding="utf-8"),
                        "name: unsafe\non: [push]\njobs: {}\n",
                        "adversarial protected workflow change",
                    ),
                ),
                confidence=0.2,
            )
        if incident.kind == "path_escape":
            return PatchCandidate(
                skill_name=self.name,
                diagnosis=diagnosis,
                edits=(FileEdit("../outside.txt", "", "owned", "adversarial workspace escape"),),
                confidence=0.0,
            )

        for source in sorted((incident.workspace / "app").glob("*.py")):
            text = source.read_text(encoding="utf-8")
            if incident.kind == "overfit_mean" and "return sum(values) / len(values)" in text:
                return PatchCandidate(
                    skill_name=self.name,
                    diagnosis=diagnosis,
                    edits=(
                        FileEdit(
                            source.relative_to(incident.workspace).as_posix(),
                            text,
                            text.replace("return sum(values) / len(values)", "return 0.0"),
                            "adversarial overfit probe",
                        ),
                    ),
                    confidence=0.3,
                )
            for old, new, reason in self.RULES:
                if old in text:
                    return PatchCandidate(
                        skill_name=self.name,
                        diagnosis=diagnosis,
                        edits=(
                            FileEdit(
                                source.relative_to(incident.workspace).as_posix(),
                                text,
                                text.replace(old, new, 1),
                                reason,
                            ),
                        ),
                        confidence=0.95,
                    )
        return PatchCandidate(self.name, diagnosis, (), 0.0)


def _workspace_root(workspace: Path) -> Path:
    """Resolve a real directory without accepting a symlink as the workspace root."""

    if workspace.is_symlink():
        raise RuntimeError("workspace root must not be a symlink")
    root = workspace.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("workspace root must be a directory")
    return root


def _validated_edits(
    workspace: Path, candidate: PatchCandidate
) -> list[tuple[Path, FileEdit, bytes | None, int]]:
    """Validate the entire edit set without following links or mutating a byte."""

    root = _workspace_root(workspace)
    validated: list[tuple[Path, FileEdit, bytes | None, int]] = []
    seen: set[str] = set()
    for edit in candidate.edits:
        if "\x00" in edit.path:
            raise RuntimeError("unsafe edit path contains a NUL byte")
        pure = PurePosixPath(edit.path)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            raise RuntimeError(f"unsafe edit path for {edit.path}")
        relative = pure.as_posix()
        if relative in seen:
            raise RuntimeError(f"duplicate edit path for {edit.path}")
        seen.add(relative)
        path = root.joinpath(*pure.parts)
        cursor = root
        for part in pure.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RuntimeError(f"symlink edit path for {edit.path}")
            if not cursor.exists():
                break
        try:
            path.resolve(strict=False).relative_to(root)
        except ValueError as error:
            raise RuntimeError(f"edit escapes workspace for {edit.path}") from error
        if path.is_symlink():
            raise RuntimeError(f"symlink edit path for {edit.path}")
        if path.exists() and not path.is_file():
            raise RuntimeError(f"edit target is not a regular file for {edit.path}")
        original = path.read_bytes() if path.exists() else None
        original_mode = path.lstat().st_mode & 0o7777 if path.exists() else 0o644
        current = original.decode("utf-8") if original is not None else ""
        if current != edit.old:
            raise RuntimeError(f"stale edit precondition for {edit.path}")
        validated.append((path, edit, original, original_mode))
    return validated


def _atomic_write(path: Path, data: bytes, mode: int, prefix: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
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


def _create_missing_parents(root: Path, path: Path) -> list[Path]:
    """Create parents one level at a time and report only directories we own."""

    created: list[Path] = []
    cursor = root
    for part in path.parent.relative_to(root).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError(f"symlink parent appeared during materialization: {cursor}")
        if cursor.exists():
            if not cursor.is_dir():
                raise RuntimeError(
                    f"non-directory parent appeared during materialization: {cursor}"
                )
            continue
        cursor.mkdir()
        created.append(cursor)
    return created


def apply_candidate(workspace: Path, candidate: PatchCandidate) -> list[str]:
    """Apply one fully preflighted candidate as a rollback-capable local transaction.

    Every edit, including stale-content and symlink checks, is validated before a
    directory or temporary file is created.  If materialization fails after one
    or more replacements, all touched targets are restored to their original
    bytes (or removed if they did not previously exist) before the error escapes.
    """

    validated = _validated_edits(workspace, candidate)
    root = _workspace_root(workspace)
    staged: list[tuple[Path, Path, FileEdit, bytes | None, int]] = []
    materialized: list[tuple[Path, bytes | None, int]] = []
    created_directories: list[Path] = []
    completed = False
    try:
        for path, edit, original, original_mode in validated:
            created_directories.extend(_create_missing_parents(root, path))
            descriptor, temporary = tempfile.mkstemp(prefix=".remedyfabric-", dir=path.parent)
            temporary_path = Path(temporary)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(edit.new)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), original_mode)
            staged.append((path, temporary_path, edit, original, original_mode))
        # Recheck the complete edit set once more immediately before the first
        # replacement.  No real target has changed yet, so this remains an
        # all-or-nothing stale/path precondition check.
        _validated_edits(root, candidate)
        for path, temporary_path, _, original, original_mode in staged:
            os.replace(temporary_path, path)
            materialized.append((path, original, original_mode))
        completed = True
        return [edit.path for _, edit, _, _ in validated]
    except Exception as error:
        rollback_failures: list[str] = []
        for path, original, original_mode in reversed(materialized):
            try:
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    _atomic_write(
                        path,
                        original,
                        original_mode,
                        ".remedyfabric-rollback-",
                    )
            except OSError as rollback_error:
                rollback_failures.append(f"{path}: {rollback_error}")
        if rollback_failures:
            raise RuntimeError(
                "candidate materialization failed and byte restoration also failed: "
                + "; ".join(rollback_failures)
            ) from error
        raise
    finally:
        for _, temporary_path, _, _, _ in staged:
            if temporary_path.exists():
                temporary_path.unlink()
        if not completed:
            for directory in reversed(created_directories):
                try:
                    directory.rmdir()
                except OSError:
                    pass
