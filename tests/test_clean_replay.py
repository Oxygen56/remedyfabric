from __future__ import annotations

import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from remedyfabric.release_integrity import CLEAN_REPLAY_BUILD_COMMAND, source_tree_digest
from scripts.run_clean_replay import (
    ROOT,
    _base_image,
    _copy_inputs,
    _receipt_marker,
    _runner_source,
    archive_members_safe,
)


class CleanReplayTests(unittest.TestCase):
    def test_build_command_forbids_uv_dist_gitignore_side_effect(self) -> None:
        self.assertIn("--clear", CLEAN_REPLAY_BUILD_COMMAND)
        self.assertIn("--no-create-gitignore", CLEAN_REPLAY_BUILD_COMMAND)
        self.assertEqual(CLEAN_REPLAY_BUILD_COMMAND[-3:], ("--out-dir", "dist", "."))

    def test_wheel_member_paths_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "unsafe.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("../escape.py", "unsafe")
            safe, count = archive_members_safe(wheel)
            self.assertFalse(safe)
            self.assertEqual(count, 1)

    def test_sdist_member_paths_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.txt"
            source.write_text("safe", encoding="utf-8")
            sdist = Path(temp) / "safe.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                archive.add(source, arcname="package/source.txt")
            safe, count = archive_members_safe(sdist)
            self.assertTrue(safe)
            self.assertEqual(count, 1)

    def test_clean_runner_explicitly_excludes_external_runtime_tests(self) -> None:
        source = _runner_source("1" * 32)
        self.assertIn("pure-python-offline", source)
        self.assertIn("sys.path.insert(0, str(ROOT))", source)
        self.assertIn("test_three_language_micro_replays_execute_for_real", source)
        self.assertIn("test_live_container_has_no_network_or_rootfs_write", source)
        self.assertIn("test_git_index_digest_matches_fresh_checkout_scope", source)
        self.assertNotIn("run_faultbench_micro_replays.py", source)

    def test_receipt_marker_requires_one_matching_nonce(self) -> None:
        output = 'CLEAN_SUITE_RESULT={"nonce":"abc","passed":true}\n'
        self.assertEqual(
            _receipt_marker(output, "CLEAN_SUITE_RESULT", "abc"),
            {"nonce": "abc", "passed": True},
        )
        self.assertIsNone(_receipt_marker(output, "CLEAN_SUITE_RESULT", "wrong"))
        self.assertIsNone(_receipt_marker(output + output, "CLEAN_SUITE_RESULT", "abc"))

    def test_base_image_requires_immutable_local_repo_digest(self) -> None:
        run = {
            "returncode": 0,
            "stdout": ('["python@sha256:' + "a" * 64 + '"]|linux/amd64|sha256:' + "b" * 64 + "\n"),
        }
        with patch("scripts.run_clean_replay._run", return_value=run):
            base = _base_image("")
        self.assertEqual(base["resolved_reference"], "python@sha256:" + "a" * 64)
        run["stdout"] = "[]|linux/amd64|sha256:" + "b" * 64 + "\n"
        with (
            patch("scripts.run_clean_replay._run", return_value=run),
            self.assertRaisesRegex(RuntimeError, "immutable local RepoDigest"),
        ):
            _base_image("")

    def test_clean_context_preserves_the_release_source_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            wheel = temporary_path / "remedyfabric-0.2.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel fixture")
            context = temporary_path / "context"
            context.mkdir()
            _copy_inputs(context, wheel, "e" * 32)
            self.assertEqual(source_tree_digest(context), source_tree_digest(ROOT))


if __name__ == "__main__":
    unittest.main()
