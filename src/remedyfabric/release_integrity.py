"""Deterministic release-source binding used by clean replay and the champion gate."""

from __future__ import annotations

import hashlib
import re
import subprocess
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

CHAMPION_VERSION = "0.2.0"
CLEAN_REPLAY_MIN_TESTS = 90
CLEAN_REPLAY_BUILD_COMMAND = (
    "uv",
    "build",
    "--offline",
    "--clear",
    "--no-create-gitignore",
    "--out-dir",
    "dist",
    ".",
)
CLEAN_REPLAY_EXTERNAL_TESTS = {
    (
        "test_container_executor.ContainerExecutorTests."
        "test_live_container_has_no_network_or_rootfs_write"
    ): "requires a Docker daemon outside the Python-only replay container",
    (
        "test_faultbench.FaultBenchTests.test_three_language_micro_replays_execute_for_real"
    ): "requires Node.js and Rust; CI final-evidence reruns it separately",
    (
        "test_delivery_validation.DeliveryValidationTests."
        "test_caption_mux_removes_audio_and_binds_complete_subtitles"
    ): "requires FFmpeg; CI final-evidence validates the frozen delivery bytes separately",
    (
        "test_package_submission.PackageSubmissionTests."
        "test_collects_only_head_files_and_explicit_generated_artifacts"
    ): "requires Git for repository-fixture semantics",
    (
        "test_package_submission.PackageSubmissionTests.test_non_post_head_evidence_must_be_tracked"
    ): "requires Git for repository-fixture semantics",
    (
        "test_package_submission.PackageSubmissionTests.test_unexpected_untracked_file_is_rejected"
    ): "requires Git for repository-fixture semantics",
    (
        "test_package_submission.PackageSubmissionTests."
        "test_ignored_untracked_file_is_also_rejected"
    ): "requires Git for repository-fixture semantics",
    (
        "test_package_submission.PackageSubmissionTests."
        "test_symlinked_generated_artifact_is_rejected"
    ): "requires Git for repository-fixture semantics",
    (
        "test_package_submission.PackageSubmissionTests.test_dirty_tracked_file_is_rejected"
    ): "requires Git for repository-fixture semantics",
    (
        "test_package_submission.PackageSubmissionTests."
        "test_direct_head_binding_catches_assume_unchanged_payload"
    ): "requires Git for repository-fixture semantics",
    (
        "test_build_champion_evidence.ChampionEvidenceBuilderTests."
        "test_current_mechanism_evidence_is_derived_from_receipts"
    ): "requires the optional PDF/video inspection dependencies and finalized delivery bytes",
    (
        "test_build_champion_evidence.ChampionEvidenceBuilderTests."
        "test_judge_delivery_is_never_inferred_from_unrelated_artifacts"
    ): "requires the optional PDF/video inspection dependencies and finalized delivery bytes",
    (
        "test_release_integrity.ReleaseIntegrityTests."
        "test_git_index_digest_matches_fresh_checkout_scope"
    ): "requires Git for repository-index semantics",
}

SOURCE_DIRECTORIES = (
    "assets",
    "src",
    "tests",
    "scripts",
    "skills",
    "faultbench",
    "competition",
    "agentteams",
    "docs",
    "site",
    ".github",
    "requirements",
)
SOURCE_FILES = (
    "pyproject.toml",
    "LICENSE",
    "README.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "competition.yaml",
    "submission/final-submission.zh.md",
)
EXCLUDED_PARTS = {
    ".git",
    ".next",
    ".ruff_cache",
    ".vercel",
    ".vinext",
    ".wrangler",
    ".yarn",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "outputs",
    "work",
}


def project_version(root: Path) -> str:
    """Read the PEP 621 project version from the release source tree."""

    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(payload["project"]["version"])


def _git_index_members(root: Path) -> list[Path] | None:
    """Return release-source members from this root's Git index when available.

    The index is the pre-commit equivalent of a clean checkout. Requiring the
    discovered Git top level to equal ``root`` prevents a temporary replay
    context nested below the project from accidentally reading its parent's
    index.
    """

    try:
        top_level = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if top_level.returncode != 0:
        return None
    try:
        if Path(top_level.stdout.strip()).resolve() != root.resolve():
            return None
    except OSError:
        return None
    try:
        listed = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--cached",
                "--",
                *SOURCE_FILES,
                *SOURCE_DIRECTORIES,
            ],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except OSError:
        return None
    members: list[Path] = []
    for raw in listed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        candidate = root / relative
        if not candidate.exists() and not candidate.is_symlink():
            raise RuntimeError(f"release source tracked by Git is missing: {relative.as_posix()}")
        members.append(candidate)
    return members


def _filesystem_members(root: Path) -> list[Path]:
    """Collect a clean-context fallback using the same explicit source scope."""

    members: list[Path] = []
    for relative in SOURCE_FILES:
        candidate = root / relative
        if candidate.is_file():
            members.append(candidate)
    for relative in SOURCE_DIRECTORIES:
        directory = root / relative
        if not directory.is_dir():
            continue
        members.extend(
            candidate
            for candidate in directory.rglob("*")
            if candidate.is_file()
            and not EXCLUDED_PARTS.intersection(candidate.parts)
            and not any(part.endswith(".egg-info") for part in candidate.parts)
            and not candidate.name.startswith(".env")
            and candidate.suffix not in {".pyc", ".pyo"}
            and candidate.suffix != ".pem"
        )
    return members


def source_tree_digest(root: Path) -> str:
    """Bind the publishable source bytes without host-specific build files.

    In a real repository this uses the Git index, so staged pre-freeze bytes
    and a subsequent fresh checkout produce the same digest. Standalone clean
    replay contexts use the explicit source allowlist fallback.
    """

    members = _git_index_members(root)
    if members is None:
        members = _filesystem_members(root)
    for member in members:
        if member.is_symlink():
            raise RuntimeError(f"release source digest refuses symlink: {member.relative_to(root)}")
    digest = hashlib.sha256()
    for member in sorted(members, key=lambda item: item.relative_to(root).as_posix()):
        relative = member.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = member.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def clean_replay_current(receipt: Mapping[str, Any] | None, root: Path) -> bool:
    """Recompute whether a clean-replay receipt covers the current release bytes."""

    if not receipt or receipt.get("passed") is not True:
        return False
    version = project_version(root)
    if version != CHAMPION_VERSION:
        return False
    archives = receipt.get("archives", [])
    if not isinstance(archives, list):
        return False
    names = {str(item.get("name", "")) for item in archives if isinstance(item, dict)}
    archive_bytes_match = all(
        isinstance(item, dict)
        and (root / "dist" / str(item.get("name", ""))).is_file()
        and hashlib.sha256((root / "dist" / str(item.get("name", ""))).read_bytes()).hexdigest()
        == item.get("sha256")
        and (root / "dist" / str(item.get("name", ""))).stat().st_size == item.get("size_bytes")
        for item in archives
    )

    environment = receipt.get("clean_environment")
    if not isinstance(environment, Mapping):
        return False
    suite = environment.get("test_suite")
    if not isinstance(suite, Mapping):
        return False
    excluded = suite.get("excluded_external_tests")
    if not isinstance(excluded, Mapping):
        return False
    semantic = environment.get("semantic_replays")
    if not isinstance(semantic, Mapping):
        return False
    external = environment.get("external_runtime_boundaries")
    if not isinstance(external, Mapping):
        return False
    package_build = receipt.get("package_build")
    expected_build = list(CLEAN_REPLAY_BUILD_COMMAND)
    base = environment.get("base_image")
    if not isinstance(base, Mapping):
        return False
    image_build = environment.get("image_build")
    replay = environment.get("replay")
    if not isinstance(image_build, Mapping) or not isinstance(replay, Mapping):
        return False
    expected_security_arguments = {
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
    }
    image_command = image_build.get("command")
    replay_command = replay.get("command")
    if not isinstance(image_command, list) or not isinstance(replay_command, list):
        return False
    return bool(
        receipt.get("project_version") == version
        and receipt.get("source_tree_digest") == source_tree_digest(root)
        and receipt.get("source_tree_unchanged_after_build") is True
        and receipt.get("unexpected_dist_members") == []
        and len(archives) == 2
        and archive_bytes_match
        and all(
            isinstance(item, dict)
            and item.get("member_paths_safe") is True
            and isinstance(item.get("sha256"), str)
            and len(item["sha256"]) == 64
            and isinstance(item.get("size_bytes"), int)
            and item["size_bytes"] > 0
            and isinstance(item.get("member_count"), int)
            and item["member_count"] > 0
            for item in archives
        )
        and f"remedyfabric-{version}-py3-none-any.whl" in names
        and f"remedyfabric-{version}.tar.gz" in names
        and isinstance(package_build, Mapping)
        and package_build.get("returncode") == 0
        and package_build.get("command") == expected_build
        and environment.get("container_image_build_network") == "none"
        and environment.get("runtime_network") == "none"
        and environment.get("rootfs_read_only") is True
        and image_build.get("returncode") == 0
        and "--network" in image_command
        and image_command[image_command.index("--network") + 1] == "none"
        and replay.get("returncode") == 0
        and expected_security_arguments.issubset(set(replay_command))
        and replay_command[-2:] == ["python", "/clean_replay_entrypoint.py"]
        and environment.get("tests_run", 0) >= CLEAN_REPLAY_MIN_TESTS
        and environment.get("tests_skipped") == 0
        and environment.get("semantic_evidence_validated") is True
        and suite.get("kind") == "pure-python-offline"
        and suite.get("passed") is True
        and suite.get("missing_expected_exclusions") == []
        and re.fullmatch(r"[0-9a-f]{32}", str(suite.get("nonce", "")))
        and suite.get("discovered_tests")
        == suite.get("executed_tests") + len(CLEAN_REPLAY_EXTERNAL_TESTS)
        and suite.get("executed_tests") == environment.get("tests_run")
        and suite.get("skipped_tests") == 0
        and excluded == CLEAN_REPLAY_EXTERNAL_TESTS
        and isinstance(suite.get("selected_test_ids_sha256"), str)
        and len(suite["selected_test_ids_sha256"]) == 64
        and set(semantic) == {"remedybench", "resilient_matrix", "quorum_model", "faultbench"}
        and all(value is True for value in semantic.values())
        and set(external)
        == {
            "node_rust_micro_replays",
            "nested_docker_isolation",
            "git_repository_fixtures",
            "delivery_inspection",
        }
        and all(str(value).startswith("not executed") for value in external.values())
        and base.get("tag") == "python:3.12-slim"
        and re.fullmatch(r"python@sha256:[0-9a-f]{64}", str(base.get("resolved_reference", "")))
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(base.get("image_id", "")))
        and re.fullmatch(r"[a-z0-9_./-]+/[a-z0-9_./-]+", str(base.get("platform", "")))
    )


def clean_replay_semantic_projection(
    receipt: Mapping[str, Any] | None,
    root: Path,
) -> dict[str, Any]:
    """Return the stable semantics of one strictly current clean replay.

    A clean replay contains intentionally per-run evidence such as nonces,
    timings, resolved image/platform identifiers, and distribution byte hashes.
    Those fields remain mandatory in :func:`clean_replay_current` and in the
    final package receipt, but they must not make a pre-rendered judge delivery
    depend on which equivalent clean replay produced the receipt.
    """

    if not clean_replay_current(receipt, root):
        raise ValueError("clean replay is not current and strictly valid")
    assert receipt is not None  # Narrowed by the strict validator above.
    environment = receipt["clean_environment"]
    suite = environment["test_suite"]
    archives = receipt["archives"]
    return {
        "schema_version": "remedyfabric.clean-replay-semantic.v1",
        "project_version": receipt["project_version"],
        "source_tree_digest": receipt["source_tree_digest"],
        "source_tree_unchanged_after_build": receipt["source_tree_unchanged_after_build"],
        "package_build": {
            "returncode": receipt["package_build"]["returncode"],
            "command": receipt["package_build"]["command"],
        },
        "archives": [
            {
                "name": archive["name"],
                "member_paths_safe": archive["member_paths_safe"],
            }
            for archive in sorted(archives, key=lambda item: str(item["name"]))
        ],
        "unexpected_dist_members": receipt["unexpected_dist_members"],
        "clean_environment": {
            "base_image_tag": environment["base_image"]["tag"],
            "container_image_build_network": environment["container_image_build_network"],
            "runtime_network": environment["runtime_network"],
            "rootfs_read_only": environment["rootfs_read_only"],
            "image_build_succeeded": environment["image_build"]["returncode"] == 0,
            "replay_succeeded": environment["replay"]["returncode"] == 0,
            "tests_run": environment["tests_run"],
            "tests_skipped": environment["tests_skipped"],
            "test_suite": {
                "kind": suite["kind"],
                "passed": suite["passed"],
                "discovered_tests": suite["discovered_tests"],
                "executed_tests": suite["executed_tests"],
                "skipped_tests": suite["skipped_tests"],
                "selected_test_ids_sha256": suite["selected_test_ids_sha256"],
                "excluded_external_tests": suite["excluded_external_tests"],
                "missing_expected_exclusions": suite["missing_expected_exclusions"],
            },
            "semantic_evidence_validated": environment["semantic_evidence_validated"],
            "semantic_replays": environment["semantic_replays"],
            "external_runtime_boundaries": environment["external_runtime_boundaries"],
        },
    }


__all__ = [
    "CHAMPION_VERSION",
    "CLEAN_REPLAY_EXTERNAL_TESTS",
    "CLEAN_REPLAY_MIN_TESTS",
    "EXCLUDED_PARTS",
    "SOURCE_DIRECTORIES",
    "SOURCE_FILES",
    "clean_replay_current",
    "clean_replay_semantic_projection",
    "project_version",
    "source_tree_digest",
]
