import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedyfabric.models import FileEdit, PatchCandidate
from remedyfabric.skills import apply_candidate
from remedyfabric.snapshot import WorkspaceSnapshot


def candidate(*edits: FileEdit) -> PatchCandidate:
    return PatchCandidate("test-skill", "safety regression", edits, 1.0)


class CandidateTransactionSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        (self.workspace / "app").mkdir(parents=True)
        (self.workspace / "app" / "one.py").write_text("one-old", encoding="utf-8")
        (self.workspace / "app" / "two.py").write_text("two-old", encoding="utf-8")
        self.baseline = WorkspaceSnapshot.capture(self.workspace)

    def assert_workspace_unchanged(self) -> None:
        self.assertTrue(self.baseline.matches(self.workspace))

    def test_traversal_and_absolute_paths_are_rejected_without_writes(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside-original")
        for unsafe_path in ("../outside.txt", str(outside)):
            with self.subTest(path=unsafe_path):
                with self.assertRaisesRegex(RuntimeError, "unsafe edit path"):
                    apply_candidate(
                        self.workspace,
                        candidate(
                            FileEdit(
                                unsafe_path,
                                "outside-original",
                                "owned",
                                "negative control",
                            )
                        ),
                    )
                self.assertEqual(outside.read_bytes(), b"outside-original")
                self.assert_workspace_unchanged()

    def test_symlinked_path_segment_is_rejected_without_external_write(self) -> None:
        outside_directory = self.root / "outside"
        outside_directory.mkdir()
        outside = outside_directory / "target.py"
        outside.write_bytes(b"outside-original")
        (self.workspace / "linked").symlink_to(outside_directory, target_is_directory=True)

        with self.assertRaisesRegex(RuntimeError, "symlink edit path"):
            apply_candidate(
                self.workspace,
                candidate(
                    FileEdit(
                        "linked/target.py",
                        "outside-original",
                        "owned",
                        "negative control",
                    )
                ),
            )

        self.assertEqual(outside.read_bytes(), b"outside-original")
        self.assertTrue((self.workspace / "linked").is_symlink())

    def test_duplicate_paths_are_rejected_before_the_first_write(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "duplicate edit path"):
            apply_candidate(
                self.workspace,
                candidate(
                    FileEdit("app/one.py", "one-old", "first", "duplicate one"),
                    FileEdit("app/./one.py", "one-old", "second", "duplicate two"),
                ),
            )
        self.assert_workspace_unchanged()

    def test_stale_multi_edit_is_rejected_before_creating_or_writing_any_target(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "stale edit precondition"):
            apply_candidate(
                self.workspace,
                candidate(
                    FileEdit("new/nested.py", "", "new", "would create directories"),
                    FileEdit("app/two.py", "not-current", "two-new", "stale second edit"),
                ),
            )
        self.assertFalse((self.workspace / "new").exists())
        self.assert_workspace_unchanged()

    def test_mid_materialization_failure_restores_all_bytes_and_new_directories(self) -> None:
        transaction = candidate(
            FileEdit("app/one.py", "one-old", "one-new", "first replacement"),
            FileEdit("new/two.py", "", "two-new", "second replacement"),
        )
        real_replace = os.replace
        candidate_replacements = 0

        def fail_second_candidate_replace(source, destination):
            nonlocal candidate_replacements
            if Path(source).name.startswith(".remedyfabric-") and not Path(source).name.startswith(
                ".remedyfabric-rollback-"
            ):
                candidate_replacements += 1
                if candidate_replacements == 2:
                    raise OSError("injected second replacement failure")
            return real_replace(source, destination)

        with (
            patch("remedyfabric.skills.os.replace", side_effect=fail_second_candidate_replace),
            self.assertRaisesRegex(OSError, "injected second replacement failure"),
        ):
            apply_candidate(self.workspace, transaction)

        self.assert_workspace_unchanged()
        self.assertFalse((self.workspace / "new").exists())

    def test_apply_and_failed_transaction_preserve_executable_mode(self) -> None:
        executable = self.workspace / "app" / "one.py"
        executable.chmod(0o755)
        apply_candidate(
            self.workspace,
            candidate(FileEdit("app/one.py", "one-old", "one-new", "mode preservation")),
        )
        self.assertEqual(executable.stat().st_mode & 0o7777, 0o755)

        executable.write_text("one-old", encoding="utf-8")
        executable.chmod(0o755)
        real_replace = os.replace

        def fail_second_candidate_replace(source, destination):
            if Path(destination).name == "two.py":
                raise OSError("injected mode rollback failure")
            return real_replace(source, destination)

        transaction = candidate(
            FileEdit("app/one.py", "one-old", "changed", "first replacement"),
            FileEdit("app/two.py", "two-old", "changed", "second replacement"),
        )
        with (
            patch("remedyfabric.skills.os.replace", side_effect=fail_second_candidate_replace),
            self.assertRaisesRegex(OSError, "injected mode rollback failure"),
        ):
            apply_candidate(self.workspace, transaction)
        self.assertEqual(executable.read_text(encoding="utf-8"), "one-old")
        self.assertEqual(executable.stat().st_mode & 0o7777, 0o755)


class WorkspaceSnapshotSafetyTests(unittest.TestCase):
    def test_snapshot_includes_src_evidence_and_restores_its_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            evidence = workspace / "src" / "evidence" / "module.py"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(b"original-evidence-bytes")
            snapshot = WorkspaceSnapshot.capture(workspace)

            self.assertIn("src/evidence/module.py", snapshot.files)
            evidence.write_bytes(b"mutated")
            snapshot.restore(workspace)

            self.assertEqual(evidence.read_bytes(), b"original-evidence-bytes")
            self.assertTrue(snapshot.matches(workspace))

    def test_snapshot_refuses_file_and_directory_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside.txt"
            outside.write_bytes(b"outside")
            for symlink_name, target in (
                ("file-link", outside),
                ("directory-link", root),
            ):
                workspace = root / f"workspace-{symlink_name}"
                workspace.mkdir()
                (workspace / symlink_name).symlink_to(target, target_is_directory=target.is_dir())
                with (
                    self.subTest(symlink=symlink_name),
                    self.assertRaisesRegex(RuntimeError, "snapshot refuses symlink"),
                ):
                    WorkspaceSnapshot.capture(workspace)

    def test_snapshot_restore_preserves_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            executable = workspace / "bin" / "run"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            snapshot = WorkspaceSnapshot.capture(workspace)

            executable.write_bytes(b"corrupted")
            executable.chmod(0o600)
            snapshot.restore(workspace)

            self.assertEqual(executable.read_bytes(), b"#!/bin/sh\nexit 0\n")
            self.assertEqual(executable.stat().st_mode & 0o7777, 0o755)
            self.assertTrue(snapshot.matches(workspace))


if __name__ == "__main__":
    unittest.main()
