from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts import package_submission as package


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        check=True,
    )


def _write(root: Path, relative: str, data: bytes = b"fixture\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_clean_ci_fixture(
    root: Path,
    *,
    clean_bytes: bytes = b'{"passed":true}\n',
) -> dict[str, object]:
    _write(
        root,
        "pyproject.toml",
        b'[project]\nname = "remedyfabric"\nversion = "0.2.0"\n',
    )
    members = {
        "artifacts/clean-replay.json": clean_bytes,
        "dist/remedyfabric-0.2.0-py3-none-any.whl": b"exact-wheel",
        "dist/remedyfabric-0.2.0.tar.gz": b"exact-sdist",
    }
    for relative, content in members.items():
        _write(root, relative, content)
    artifact_zip = root / package.CLEAN_ARTIFACT_ZIP_PATH
    artifact_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact_zip, "w") as archive:
        for relative, content in members.items():
            info = zipfile.ZipInfo(relative)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, content)
    observed = package.inspect_clean_release_artifact_zip(artifact_zip, version="0.2.0")
    return {
        "clean_release_artifact": {
            "metadata": {"digest": f"sha256:{observed['sha256']}"},
            "zip": observed,
        }
    }


@contextmanager
def _reduced_layout() -> object:
    with ExitStack() as stack:
        stack.enter_context(patch.object(package, "ROOT_FILES", ("README.md",)))
        stack.enter_context(patch.object(package, "SOURCE_DIRECTORIES", ("src",)))
        stack.enter_context(patch.object(package, "REQUIREMENT_FILES", ()))
        stack.enter_context(
            patch.object(package, "SUBMISSION_FILES", ("submission/final-submission.zh.md",))
        )
        stack.enter_context(patch.object(package, "ARTIFACTS", ("artifacts/evidence.json",)))
        stack.enter_context(
            patch.object(
                package,
                "POST_HEAD_GENERATED_ARTIFACTS",
                ("artifacts/evidence.json",),
            )
        )
        yield


def _make_reduced_repository(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Release Test")
    _git(root, "config", "user.email", "release-test@example.invalid")
    _write(root, "README.md")
    _write(root, "src/tool.py", b"VALUE = 1\n")
    _write(root, "submission/final-submission.zh.md")
    _git(root, "add", "README.md", "src/tool.py", "submission/final-submission.zh.md")
    _git(root, "-c", "commit.gpgsign=false", "commit", "-qm", "initial")
    _write(root, "artifacts/evidence.json", b"{}\n")
    _write(root, "dist/remedyfabric-0.2.0-py3-none-any.whl")
    _write(root, "dist/remedyfabric-0.2.0.tar.gz")


class PackageSubmissionTests(unittest.TestCase):
    def test_script_help_runs_without_project_root_on_pythonpath(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/package_submission.py", "--help"],
            cwd=package.ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Build a deterministic GOAI archive", completed.stdout)

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_collects_only_head_files_and_explicit_generated_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            members = package.collect_members(root=root, version="0.2.0")
            relative = {path.relative_to(root).as_posix() for path in members}
            self.assertEqual(
                relative,
                {
                    "README.md",
                    "artifacts/evidence.json",
                    "dist/remedyfabric-0.2.0-py3-none-any.whl",
                    "dist/remedyfabric-0.2.0.tar.gz",
                    "src/tool.py",
                    "submission/final-submission.zh.md",
                },
            )

    def test_release_layout_requires_requirements_and_final_submission(self) -> None:
        self.assertEqual(
            set(package.REQUIREMENT_FILES),
            {"requirements/pdf.txt", "requirements/video.txt"},
        )
        self.assertIn("submission/final-submission.zh.md", package.SUBMISSION_FILES)
        self.assertIn("artifacts/benchmark.json", package.ARTIFACTS)
        self.assertIn("artifacts/agentteams-runtime-blocked.json", package.ARTIFACTS)
        self.assertEqual(
            set(package.POST_HEAD_GENERATED_ARTIFACTS),
            {
                "artifacts/public-ci.json",
                "artifacts/clean-release-ci.zip",
                "artifacts/champion-evidence.json",
                "artifacts/champion-gate.json",
                "artifacts/clean-replay.json",
            },
        )

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_non_post_head_evidence_must_be_tracked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            with (
                patch.object(package, "POST_HEAD_GENERATED_ARTIFACTS", ()),
                self.assertRaisesRegex(RuntimeError, "not tracked by HEAD"),
            ):
                package.collect_members(root=root, version="0.2.0")

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_unexpected_untracked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            _write(root, "notes/private.txt")
            with self.assertRaisesRegex(RuntimeError, "unexpected untracked"):
                package.collect_members(root=root, version="0.2.0")

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_ignored_untracked_file_is_also_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            _write(root, ".gitignore", b"private.bin\n")
            _git(root, "add", ".gitignore")
            _git(root, "-c", "commit.gpgsign=false", "commit", "-qm", "ignore fixture")
            _write(root, "private.bin", b"private")
            with self.assertRaisesRegex(RuntimeError, "unexpected untracked"):
                package.collect_members(root=root, version="0.2.0")

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_symlinked_generated_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            artifact = root / "artifacts/evidence.json"
            artifact.unlink()
            artifact.symlink_to(root / "README.md")
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                package.collect_members(root=root, version="0.2.0")

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_dirty_tracked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            _write(root, "README.md", b"changed\n")
            failures = package._worktree_failures(root, "0.2.0")
            self.assertTrue(any("README.md" in failure for failure in failures))

    @unittest.skipUnless(shutil.which("git"), "git is required for repository fixtures")
    def test_direct_head_binding_catches_assume_unchanged_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, _reduced_layout():
            root = Path(temporary)
            _make_reduced_repository(root)
            _git(root, "update-index", "--assume-unchanged", "README.md")
            _write(root, "README.md", b"locally tampered but hidden from ordinary diff\n")
            members = package.collect_members(root=root, version="0.2.0")
            failures = package._head_member_failures(members, root)
            self.assertTrue(any("README.md" in failure for failure in failures))

    def test_clean_archive_check_delegates_to_current_release_integrity_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            _write(
                root,
                "pyproject.toml",
                b'[project]\nname = "remedyfabric"\nversion = "0.2.0"\n',
            )
            wheel = dist / "remedyfabric-0.2.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("remedyfabric/__init__.py", "")
            source_file = _write(root, "source.txt")
            source_archive = dist / "remedyfabric-0.2.0.tar.gz"
            with tarfile.open(source_archive, "w:gz") as archive:
                archive.add(source_file, arcname="remedyfabric-0.2.0/source.txt")

            clean = {"passed": True}
            with patch.object(package, "clean_replay_current", return_value=True) as validator:
                self.assertEqual(package._clean_archive_failures(clean, root=root), [])
            validator.assert_called_once_with(clean, root)

            with patch.object(package, "clean_replay_current", return_value=False) as validator:
                failures = package._clean_archive_failures(clean, root=root)
            validator.assert_called_once_with(clean, root)
            self.assertIn(
                "clean replay does not satisfy the current release integrity contract",
                failures,
            )

    def test_nested_distribution_privacy_and_links_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel = root / "remedyfabric-0.2.0-py3-none-any.whl"
            host_path = "/" + "Users" + "/example/repo"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("remedyfabric/receipt.json", f'{{"root":"{host_path}"}}')
            wheel_failures = package._distribution_archive_failures(wheel)
            self.assertTrue(any("host_home_path" in failure for failure in wheel_failures))

            source = root / "remedyfabric-0.2.0.tar.gz"
            with tarfile.open(source, "w:gz") as archive:
                link = tarfile.TarInfo("remedyfabric-0.2.0/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside"
                archive.addfile(link)
            source_failures = package._distribution_archive_failures(source)
            self.assertTrue(any("contains a link" in failure for failure in source_failures))

    def test_clean_ci_artifact_is_bound_byte_exact_to_final_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public_ci = _make_clean_ci_fixture(root)
            self.assertEqual(
                package._clean_ci_artifact_failures(public_ci, root=root),
                [],
            )

            _write(root, "dist/remedyfabric-0.2.0-py3-none-any.whl", b"tampered-wheel")
            failures = package._clean_ci_artifact_failures(public_ci, root=root)
            self.assertTrue(any("not byte-exact" in failure for failure in failures))

    def test_clean_ci_artifact_rejects_github_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public_ci = _make_clean_ci_fixture(root)
            public_ci["clean_release_artifact"]["metadata"]["digest"] = (  # type: ignore[index]
                "sha256:" + "0" * 64
            )
            failures = package._clean_ci_artifact_failures(public_ci, root=root)
            self.assertTrue(any("GitHub artifact digest" in failure for failure in failures))

    def test_clean_ci_artifact_rejects_nested_privacy_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host_path = "/" + "Users" + "/example/private"
            public_ci = _make_clean_ci_fixture(
                root,
                clean_bytes=json.dumps({"root": host_path}).encode(),
            )
            failures = package._clean_ci_artifact_failures(public_ci, root=root)
            self.assertTrue(any("privacy violation" in failure for failure in failures))

    def test_raw_binary_privacy_marker_is_rejected(self) -> None:
        failures = package._raw_privacy_markers(
            "artifact.bin",
            b"binary-prefix\x00/" + b"Users" + b"/example/private-project\x00binary-suffix",
        )
        self.assertTrue(any("host_home_path" in failure for failure in failures))

    def test_delivery_receipt_is_bound_to_current_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            delivery: dict[str, object] = {
                "passed": True,
                "checks": {check: True for check in package.DELIVERY_CHECKS},
            }
            for label, relative in package.DELIVERY_ARTIFACTS.items():
                path = _write(root, relative, label.encode())
                delivery[label] = {
                    "passed": True,
                    "path": relative,
                    "sha256": _sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            with patch.object(package, "validate_delivery_receipt", return_value=[]):
                self.assertEqual(package._delivery_failures(delivery, root), [])
            _write(root, package.DELIVERY_ARTIFACTS["video"], b"modified")
            with patch.object(package, "validate_delivery_receipt", return_value=[]):
                failures = package._delivery_failures(delivery, root)
            self.assertTrue(any("video receipt hash" in failure for failure in failures))

    def test_preflight_calls_live_validators_and_fails_closed(self) -> None:
        payloads = {
            "artifacts/champion-gate.json": {"status": "ready", "failures": []},
            "competition/champion-contract.json": {"required_gates": {}},
            "artifacts/champion-evidence.json": {"manifest_evidence_digest": "digest"},
            "artifacts/clean-replay.json": {"passed": True},
            "artifacts/agentteams-live-evidence.json": {"validation": {"passed": True}},
            "artifacts/delivery-qa.json": {"passed": True},
            "artifacts/public-ci.json": {
                "repository": "Oxygen56/remedyfabric",
                "conclusion": "success",
                "head_sha": "b" * 40,
                "html_url": "https://github.com/Oxygen56/remedyfabric/actions/runs/123",
                "jobs": {job: "success" for job in package.REQUIRED_PUBLIC_CI_JOBS},
            },
        }

        def load(relative: str, *, root: Path) -> dict[str, object]:
            del root
            return payloads[relative]

        with (
            patch.object(package, "_load", side_effect=load),
            patch.object(package, "project_version", return_value="0.2.0"),
            patch.object(package, "source_tree_digest", return_value="a" * 64),
            patch.object(package, "_worktree_failures", return_value=[]),
            patch.object(package, "_head_member_failures", return_value=[]),
            patch.object(package, "validate_manifest_integrity", return_value=[]) as integrity,
            patch.object(package, "validate_runtime_semantics", return_value=[]) as semantics,
            patch.object(package, "evaluate", return_value=[]) as thresholds,
            patch.object(package, "live_evidence_is_valid", return_value=True) as live,
            patch.object(package, "_clean_archive_failures", return_value=[]),
            patch.object(package, "_delivery_failures", return_value=[]),
            patch.object(package, "_public_ci_failures", return_value=[]),
            patch.object(package, "_clean_ci_artifact_failures", return_value=[]),
            patch.object(package, "scan_paths", return_value=[]),
        ):
            result = package._preflight([], root=Path("/tmp/release-test"), commit="b" * 40)
            self.assertEqual(result["version"], "0.2.0")
            integrity.assert_called_once()
            semantics.assert_called_once_with(Path("/tmp/release-test"))
            thresholds.assert_called_once()
            live.assert_called_once_with(payloads["artifacts/agentteams-live-evidence.json"])
            live.return_value = False
            with self.assertRaisesRegex(RuntimeError, "AgentTeams"):
                package._preflight([], root=Path("/tmp/release-test"), commit="b" * 40)

    def test_preflight_rejects_live_semantic_failure(self) -> None:
        payloads = {
            "artifacts/champion-gate.json": {
                "status": "not_ready",
                "failures": ["semantic.runtime: mismatch"],
            },
            "competition/champion-contract.json": {"required_gates": {}},
            "artifacts/champion-evidence.json": {"manifest_evidence_digest": "digest"},
            "artifacts/clean-replay.json": {"passed": True},
            "artifacts/agentteams-live-evidence.json": {"validation": {"passed": True}},
            "artifacts/delivery-qa.json": {"passed": True},
            "artifacts/public-ci.json": {},
        }

        def load(relative: str, *, root: Path) -> dict[str, object]:
            del root
            return payloads[relative]

        with (
            patch.object(package, "_load", side_effect=load),
            patch.object(package, "project_version", return_value="0.2.0"),
            patch.object(package, "source_tree_digest", return_value="a" * 64),
            patch.object(package, "_worktree_failures", return_value=[]),
            patch.object(package, "_head_member_failures", return_value=[]),
            patch.object(package, "validate_manifest_integrity", return_value=[]),
            patch.object(
                package,
                "validate_runtime_semantics",
                return_value=["semantic.runtime: mismatch"],
            ),
            patch.object(package, "evaluate", return_value=[]),
            patch.object(package, "live_evidence_is_valid", return_value=True),
            patch.object(package, "_clean_archive_failures", return_value=[]),
            patch.object(package, "_delivery_failures", return_value=[]),
            patch.object(package, "_public_ci_failures", return_value=[]),
            patch.object(package, "_clean_ci_artifact_failures", return_value=[]),
            patch.object(package, "scan_paths", return_value=[]),
            self.assertRaisesRegex(RuntimeError, "champion evidence failed live"),
        ):
            package._preflight([], root=Path("/tmp/release-test"), commit="b" * 40)

    def test_public_ci_preflight_delegates_to_strict_live_validator(self) -> None:
        commit = "c" * 40
        receipt = {
            "schema_version": "1.0",
            "repository": "Oxygen56/remedyfabric",
            "workflow_path": ".github/workflows/ci.yml",
            "run_id": 456,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "head_sha": commit,
            "html_url": "https://github.com/Oxygen56/remedyfabric/actions/runs/456",
            "jobs": {job: "success" for job in package.REQUIRED_PUBLIC_CI_JOBS},
            "live_run_payload_sha256": "e" * 64,
            "live_jobs_payload_sha256": "f" * 64,
        }
        with patch.object(package, "validate_public_ci_receipt", return_value=[]) as validator:
            self.assertEqual(package._public_ci_failures(receipt, commit), [])
        validator.assert_called_once_with(receipt, commit, live=True)

    def test_final_zip_reverification_binds_bytes_modes_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "submission.zip"
            payload = b"#!/bin/sh\nexit 0\n"
            records = [
                {
                    "path": "scripts/replay.sh",
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "mode": "0755",
                }
            ]
            manifest = {"files": records}
            manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
            with zipfile.ZipFile(archive_path, "w") as archive:
                info = zipfile.ZipInfo("scripts/replay.sh")
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, payload)
                manifest_info = zipfile.ZipInfo("SUBMISSION_MANIFEST.json")
                manifest_info.create_system = 3
                manifest_info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(manifest_info, manifest_bytes)
            self.assertEqual(
                package._verify_final_archive(
                    archive_path,
                    records=records,
                    manifest_bytes=manifest_bytes,
                ),
                [],
            )

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive_path, "a") as archive:
                    duplicate = zipfile.ZipInfo("scripts/replay.sh")
                    duplicate.create_system = 3
                    duplicate.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(duplicate, b"tampered")
            failures = package._verify_final_archive(
                archive_path,
                records=records,
                manifest_bytes=manifest_bytes,
            )
            self.assertTrue(any("duplicate" in failure for failure in failures))
            self.assertTrue(any("mismatch" in failure for failure in failures))

    def test_archive_mode_preserves_executable_bit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = _write(root, "scripts/replay.py")
            document = _write(root, "README.md")
            script.chmod(0o755)
            document.chmod(0o644)
            self.assertEqual(package._archive_mode(script), 0o100755)
            self.assertEqual(package._archive_mode(document), 0o100644)


if __name__ == "__main__":
    unittest.main()
