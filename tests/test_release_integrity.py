from __future__ import annotations

import copy
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedyfabric.release_integrity import (
    CLEAN_REPLAY_EXTERNAL_TESTS,
    clean_replay_current,
    clean_replay_semantic_projection,
    project_version,
    source_tree_digest,
)


class ReleaseIntegrityTests(unittest.TestCase):
    def _valid_clean_receipt(self, root: Path) -> dict[str, object]:
        (root / "dist").mkdir(exist_ok=True)
        (root / "pyproject.toml").write_text(
            '[project]\nname = "remedyfabric"\nversion = "0.2.0"\n', encoding="utf-8"
        )
        archives = []
        for name in (
            "remedyfabric-0.2.0-py3-none-any.whl",
            "remedyfabric-0.2.0.tar.gz",
        ):
            path = root / "dist" / name
            path.write_bytes((name + "\n").encode())
            archives.append(
                {
                    "name": name,
                    "member_paths_safe": True,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                    "member_count": 1,
                }
            )
        executed = 93
        return {
            "passed": True,
            "project_version": "0.2.0",
            "source_tree_digest": source_tree_digest(root),
            "source_tree_unchanged_after_build": True,
            "unexpected_dist_members": [],
            "package_build": {
                "returncode": 0,
                "command": [
                    "uv",
                    "build",
                    "--offline",
                    "--clear",
                    "--no-create-gitignore",
                    "--out-dir",
                    "dist",
                    ".",
                ],
                "duration_ms": 1.0,
            },
            "archives": archives,
            "clean_environment": {
                "container_image_build_network": "none",
                "runtime_network": "none",
                "rootfs_read_only": True,
                "image_build": {
                    "returncode": 0,
                    "command": ["docker", "build", "--network", "none", "."],
                    "duration_ms": 2.0,
                },
                "replay": {
                    "returncode": 0,
                    "command": [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "--pids-limit",
                        "128",
                        "--memory",
                        "512m",
                        "--cpus",
                        "1.0",
                        "fixture-image",
                        "python",
                        "/clean_replay_entrypoint.py",
                    ],
                    "duration_ms": 3.0,
                },
                "tests_run": executed,
                "tests_skipped": 0,
                "semantic_evidence_validated": True,
                "semantic_replays": {
                    "remedybench": True,
                    "resilient_matrix": True,
                    "quorum_model": True,
                    "faultbench": True,
                },
                "external_runtime_boundaries": {
                    "node_rust_micro_replays": "not executed here",
                    "nested_docker_isolation": "not executed here",
                    "git_repository_fixtures": "not executed here",
                    "delivery_inspection": "not executed here",
                },
                "base_image": {
                    "tag": "python:3.12-slim",
                    "resolved_reference": "python@sha256:" + "a" * 64,
                    "image_id": "sha256:" + "b" * 64,
                    "platform": "linux/amd64",
                },
                "test_suite": {
                    "kind": "pure-python-offline",
                    "passed": True,
                    "nonce": "d" * 32,
                    "missing_expected_exclusions": [],
                    "discovered_tests": executed + len(CLEAN_REPLAY_EXTERNAL_TESTS),
                    "executed_tests": executed,
                    "skipped_tests": 0,
                    "selected_test_ids_sha256": "c" * 64,
                    "excluded_external_tests": CLEAN_REPLAY_EXTERNAL_TESTS,
                },
            },
        }

    def test_digest_changes_with_release_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/package").mkdir(parents=True)
            (root / "src/package/core.py").write_text("VALUE = 1\n", encoding="utf-8")
            first = source_tree_digest(root)
            (root / "src/package/core.py").write_text("VALUE = 2\n", encoding="utf-8")
            self.assertNotEqual(first, source_tree_digest(root))

    def test_digest_falls_back_to_explicit_source_scope_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/package").mkdir(parents=True)
            source = root / "src/package/core.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            with patch(
                "remedyfabric.release_integrity.subprocess.run",
                side_effect=FileNotFoundError("git is absent"),
            ):
                first = source_tree_digest(root)
                source.write_text("VALUE = 2\n", encoding="utf-8")
                second = source_tree_digest(root)
            self.assertNotEqual(first, second)

    def test_git_index_digest_matches_fresh_checkout_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/package").mkdir(parents=True)
            tracked = root / "src/package/core.py"
            tracked.write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "src/package/core.py"], cwd=root, check=True)
            indexed = source_tree_digest(root)

            # Ignored or merely untracked build products are absent from a
            # fresh checkout and therefore must not perturb the source bind.
            (root / "site/dist").mkdir(parents=True)
            (root / "site/dist/index.html").write_text("generated", encoding="utf-8")
            (root / "src/package/local.py").write_text("LOCAL = True\n", encoding="utf-8")
            self.assertEqual(indexed, source_tree_digest(root))

            tracked.write_text("VALUE = 2\n", encoding="utf-8")
            changed = source_tree_digest(root)
            self.assertNotEqual(indexed, changed)
            subprocess.run(["git", "add", "src/package/core.py"], cwd=root, check=True)
            self.assertEqual(changed, source_tree_digest(root))

    def test_project_version_reads_pep621_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "example"\nversion = "2.3.4"\n', encoding="utf-8"
            )
            self.assertEqual(project_version(root), "2.3.4")

    def test_clean_receipt_requires_real_matching_archives_and_semantic_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "remedyfabric"\nversion = "0.2.0"\n', encoding="utf-8"
            )
            receipt = {
                "passed": True,
                "project_version": "0.2.0",
                "source_tree_digest": source_tree_digest(root),
                "source_tree_unchanged_after_build": True,
                "unexpected_dist_members": [],
                "archives": [
                    {
                        "name": "remedyfabric-0.2.0-py3-none-any.whl",
                        "member_paths_safe": True,
                        "sha256": "0" * 64,
                        "size_bytes": 1,
                    },
                    {
                        "name": "remedyfabric-0.2.0.tar.gz",
                        "member_paths_safe": True,
                        "sha256": "0" * 64,
                        "size_bytes": 1,
                    },
                ],
                "clean_environment": {
                    "tests_run": 99,
                    "tests_skipped": 0,
                    "semantic_evidence_validated": True,
                },
            }
            self.assertFalse(clean_replay_current(receipt, root))

    def test_complete_clean_receipt_is_bound_to_020_archives_and_declared_suite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dist").mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "remedyfabric"\nversion = "0.2.0"\n', encoding="utf-8"
            )
            archives = []
            for name in (
                "remedyfabric-0.2.0-py3-none-any.whl",
                "remedyfabric-0.2.0.tar.gz",
            ):
                path = root / "dist" / name
                path.write_bytes((name + "\n").encode())
                archives.append(
                    {
                        "name": name,
                        "member_paths_safe": True,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "size_bytes": path.stat().st_size,
                        "member_count": 1,
                    }
                )
            executed = 93
            receipt = {
                "passed": True,
                "project_version": "0.2.0",
                "source_tree_digest": source_tree_digest(root),
                "source_tree_unchanged_after_build": True,
                "unexpected_dist_members": [],
                "package_build": {
                    "returncode": 0,
                    "command": [
                        "uv",
                        "build",
                        "--offline",
                        "--clear",
                        "--no-create-gitignore",
                        "--out-dir",
                        "dist",
                        ".",
                    ],
                },
                "archives": archives,
                "clean_environment": {
                    "container_image_build_network": "none",
                    "runtime_network": "none",
                    "rootfs_read_only": True,
                    "image_build": {
                        "returncode": 0,
                        "command": ["docker", "build", "--network", "none", "."],
                    },
                    "replay": {
                        "returncode": 0,
                        "command": [
                            "docker",
                            "run",
                            "--rm",
                            "--network",
                            "none",
                            "--read-only",
                            "--cap-drop",
                            "ALL",
                            "--security-opt",
                            "no-new-privileges:true",
                            "--pids-limit",
                            "128",
                            "--memory",
                            "512m",
                            "--cpus",
                            "1.0",
                            "fixture-image",
                            "python",
                            "/clean_replay_entrypoint.py",
                        ],
                    },
                    "tests_run": executed,
                    "tests_skipped": 0,
                    "semantic_evidence_validated": True,
                    "semantic_replays": {
                        "remedybench": True,
                        "resilient_matrix": True,
                        "quorum_model": True,
                        "faultbench": True,
                    },
                    "external_runtime_boundaries": {
                        "node_rust_micro_replays": "not executed here",
                        "nested_docker_isolation": "not executed here",
                        "git_repository_fixtures": "not executed here",
                        "delivery_inspection": "not executed here",
                    },
                    "base_image": {
                        "tag": "python:3.12-slim",
                        "resolved_reference": "python@sha256:" + "a" * 64,
                        "image_id": "sha256:" + "b" * 64,
                        "platform": "linux/amd64",
                    },
                    "test_suite": {
                        "kind": "pure-python-offline",
                        "passed": True,
                        "nonce": "d" * 32,
                        "missing_expected_exclusions": [],
                        "discovered_tests": executed + len(CLEAN_REPLAY_EXTERNAL_TESTS),
                        "executed_tests": executed,
                        "skipped_tests": 0,
                        "selected_test_ids_sha256": "c" * 64,
                        "excluded_external_tests": CLEAN_REPLAY_EXTERNAL_TESTS,
                    },
                },
            }
            self.assertTrue(clean_replay_current(receipt, root))
            receipt["clean_environment"]["test_suite"]["excluded_external_tests"] = {}  # type: ignore[index]
            self.assertFalse(clean_replay_current(receipt, root))

    def test_semantic_projection_excludes_per_run_values_but_binds_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self._valid_clean_receipt(root)
            second = copy.deepcopy(first)
            second["package_build"]["duration_ms"] = 91.0  # type: ignore[index]
            environment = second["clean_environment"]  # type: ignore[assignment]
            environment["image_build"]["duration_ms"] = 92.0  # type: ignore[index]
            environment["replay"]["duration_ms"] = 93.0  # type: ignore[index]
            environment["test_suite"]["nonce"] = "e" * 32  # type: ignore[index]
            environment["base_image"] = {  # type: ignore[index]
                "tag": "python:3.12-slim",
                "resolved_reference": "python@sha256:" + "f" * 64,
                "image_id": "sha256:" + "0" * 64,
                "platform": "linux/arm64",
            }
            self.assertTrue(clean_replay_current(first, root))
            self.assertTrue(clean_replay_current(second, root))
            self.assertEqual(
                clean_replay_semantic_projection(first, root),
                clean_replay_semantic_projection(second, root),
            )

            second["clean_environment"]["test_suite"][  # type: ignore[index]
                "selected_test_ids_sha256"
            ] = "9" * 64
            self.assertTrue(clean_replay_current(second, root))
            self.assertNotEqual(
                clean_replay_semantic_projection(first, root),
                clean_replay_semantic_projection(second, root),
            )

    def test_semantic_projection_rejects_non_current_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = self._valid_clean_receipt(root)
            receipt["clean_environment"]["semantic_replays"]["faultbench"] = False  # type: ignore[index]
            with self.assertRaisesRegex(ValueError, "not current"):
                clean_replay_semantic_projection(receipt, root)


if __name__ == "__main__":
    unittest.main()
