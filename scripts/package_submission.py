#!/usr/bin/env python3
"""Build a deterministic GOAI archive only from HEAD-bound, verified evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

# Packaging itself must not create ignored bytecode after the cleanliness check.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
for import_root in (SOURCE_ROOT, ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from remedyfabric.agentteams_evidence import live_evidence_is_valid
from remedyfabric.delivery_validation import validate_delivery_receipt
from remedyfabric.public_ci_validation import (
    CLEAN_ARTIFACT_ZIP_PATH,
    RECEIPT_JOB_ALIASES,
    expected_clean_artifact_members,
    inspect_clean_release_artifact_zip,
    validate_public_ci_receipt,
)
from remedyfabric.release_integrity import clean_replay_current, project_version, source_tree_digest
from scripts.champion_gate import evaluate, validate_manifest_integrity, validate_runtime_semantics
from scripts.check_public_release import PATTERNS, TEXT_SUFFIXES, scan_paths, scan_zip
from scripts.run_clean_replay import archive_members_safe

DEFAULT_OUTPUT = ROOT / "submission/RemedyFabric-GOAI-2026-Agent-Infra-champion.zip"

ROOT_FILES = (
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "competition.yaml",
    "pyproject.toml",
)
SOURCE_DIRECTORIES = (
    ".github",
    "agentteams",
    "assets",
    "competition",
    "docs",
    "faultbench",
    "scripts",
    "site",
    "skills",
    "src",
    "tests",
)
REQUIREMENT_FILES = ("requirements/pdf.txt", "requirements/video.txt")
SUBMISSION_FILES = ("submission/final-submission.zh.md",)
ARTIFACTS = (
    "artifacts/agentteams-live-evidence.json",
    "artifacts/agentteams-runtime-blocked.json",
    "artifacts/benchmark.json",
    "artifacts/champion-evidence.json",
    "artifacts/champion-gate.json",
    "artifacts/clean-replay.json",
    CLEAN_ARTIFACT_ZIP_PATH,
    "artifacts/container-isolation.json",
    "artifacts/dashboard.html",
    "artifacts/delivery-qa.json",
    "artifacts/faultbench-micro-replays.json",
    "artifacts/faultbench-results.json",
    "artifacts/faultbench-source-verification.json",
    "artifacts/public-ci.json",
    "artifacts/quorum-model.json",
    "artifacts/remedyfabric-champion-demo.mp4",
    "artifacts/resilient-matrix.json",
    "artifacts/video-preview.jpg",
    "output/pdf/remedyfabric-goai-agent-infra-champion.pdf",
)
POST_HEAD_GENERATED_ARTIFACTS = (
    "artifacts/public-ci.json",
    "artifacts/champion-evidence.json",
    "artifacts/champion-gate.json",
    "artifacts/clean-replay.json",
    CLEAN_ARTIFACT_ZIP_PATH,
)
DELIVERY_ARTIFACTS = {
    "pdf": "output/pdf/remedyfabric-goai-agent-infra-champion.pdf",
    "video": "artifacts/remedyfabric-champion-demo.mp4",
    "dashboard": "artifacts/dashboard.html",
}
DELIVERY_CHECKS = {
    "pdf_structure",
    "video_structure",
    "preview_structure",
    "dashboard_self_contained",
    "visual_inspection",
}
REQUIRED_PUBLIC_CI_JOBS = (
    "python-3.11",
    "python-3.13",
    "release-package",
    "evidence-site",
    "final-evidence",
)
assert set(REQUIRED_PUBLIC_CI_JOBS) == RECEIPT_JOB_ALIASES
RAW_PRIVACY_PATTERNS = {
    "host_home_path": re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+"),
    "private_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "openai_style_key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "aws_access_key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "alibaba_access_key": re.compile(rb"\bLTAI[A-Za-z0-9]{12,}\b"),
    "github_token": re.compile(rb"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "matrix_token": re.compile(rb"\bsyt_[A-Za-z0-9._=-]{16,}\b"),
    "basic_authorization": re.compile(rb"\bAuthorization\s*[:=]\s*Basic\s+\S+", re.IGNORECASE),
    "jwt_bearer": re.compile(rb"\bBearer\s+eyJ[A-Za-z0-9._-]+", re.IGNORECASE),
    "secret_environment_assignment": re.compile(
        rb"\b(?:TOKEN|API[_-]?KEY|ACCESS[_-]?TOKEN|ACCESS[_-]?KEY(?:[_-]?SECRET)?|"
        rb"PASSWORD|SECRET)\s*=\s*(?!\[REDACTED\]|none\b|null\b|false\b|true\b|0\b)"
        rb"[^\s,;\]\}\"']{8,}",
        re.IGNORECASE,
    ),
    "unresolved_placeholder": re.compile(
        rb"<(?:FINAL|TODO|TBD|PLACEHOLDER|INSERT|CHANGEME)[A-Z0-9_-]*>",
        re.IGNORECASE,
    ),
    "unredacted_secret_field": re.compile(
        rb'["\'](?:api[_-]?key|access[_-]?token|password|secret)["\']\s*:\s*'
        rb'["\'](?!\[REDACTED\]|none|null|false|true|0|\s*["\'])[^"\']{8,}["\']',
        re.IGNORECASE,
    ),
}


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def _git_paths(root: Path, *arguments: str) -> set[str]:
    output = _run_git(root, *arguments)
    return {item.decode("utf-8", errors="surrogateescape") for item in output.split(b"\0") if item}


def _head_commit(root: Path) -> str:
    commit = _run_git(root, "rev-parse", "HEAD").decode("ascii", errors="strict").strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RuntimeError("HEAD did not resolve to a full Git commit")
    return commit


def _tracked_paths(root: Path) -> set[str]:
    return _git_paths(root, "ls-files", "-z")


def _tracked_changes(root: Path) -> set[str]:
    return _git_paths(root, "diff", "--name-only", "-z", "HEAD", "--")


def _untracked_paths(root: Path) -> set[str]:
    visible = _git_paths(root, "ls-files", "--others", "--exclude-standard", "-z")
    ignored = _git_paths(
        root,
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "-z",
    )
    return visible | ignored


def _expected_archive_paths(version: str) -> set[str]:
    return {
        f"dist/remedyfabric-{version}-py3-none-any.whl",
        f"dist/remedyfabric-{version}.tar.gz",
    }


def _explicit_generated_paths(version: str) -> set[str]:
    return {*POST_HEAD_GENERATED_ARTIFACTS, *_expected_archive_paths(version)}


def _is_allowed_tracked(relative: str) -> bool:
    exact = {*ROOT_FILES, *REQUIREMENT_FILES, *SUBMISSION_FILES, *ARTIFACTS}
    if relative in exact:
        return True
    path = PurePosixPath(relative)
    return bool(path.parts and path.parts[0] in SOURCE_DIRECTORIES)


def _validate_regular_member(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    try:
        relative.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise RuntimeError(f"submission member path is not valid UTF-8: {relative!r}") from error
    if (
        pure.is_absolute()
        or not pure.parts
        or ".." in pure.parts
        or "\\" in relative
        or "\x00" in relative
        or pure.as_posix() != relative
    ):
        raise RuntimeError(f"unsafe submission member path: {relative!r}")
    current = root
    for part in pure.parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError(f"submission member traverses a symlink: {relative}")
    try:
        mode = current.lstat().st_mode
    except FileNotFoundError as error:
        raise FileNotFoundError(f"required submission member is missing: {relative}") from error
    if not stat.S_ISREG(mode):
        raise RuntimeError(f"submission member is not a regular file: {relative}")
    return current


def _snapshot_member(root: Path, member: Path) -> tuple[str, bytes, int]:
    """Read one regular file without following a final-component symlink."""

    relative = member.relative_to(root).as_posix()
    validated = _validate_regular_member(root, relative)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(validated, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"submission member changed type while reading: {relative}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    after = validated.lstat()
    if (
        not stat.S_ISREG(after.st_mode)
        or after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
        or after.st_ctime_ns != metadata.st_ctime_ns
        or stat.S_IMODE(after.st_mode) != stat.S_IMODE(metadata.st_mode)
        or sum(map(len, chunks)) != metadata.st_size
    ):
        raise RuntimeError(f"submission member changed while reading: {relative}")
    return relative, b"".join(chunks), metadata.st_mode


def _format_paths(paths: set[str]) -> str:
    ordered = sorted(paths)
    visible = ordered[:25]
    suffix = f", ... (+{len(ordered) - len(visible)} more)" if len(ordered) > len(visible) else ""
    return ", ".join(visible) + suffix


def _text_privacy_markers(name: str, content: bytes) -> list[str]:
    if PurePosixPath(name).suffix.lower() not in TEXT_SUFFIXES:
        return []
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return [f"invalid UTF-8 in text member: {name}"]
    return [f"{marker} in {name}" for marker, pattern in PATTERNS.items() if pattern.search(text)]


def _raw_privacy_markers(name: str, content: bytes) -> list[str]:
    return [
        f"{marker} in {name}"
        for marker, pattern in RAW_PRIVACY_PATTERNS.items()
        if pattern.search(content)
    ]


def _distribution_archive_failures(path: Path) -> list[str]:
    """Recursively inspect built wheel/sdist paths, members, bytes and privacy markers."""

    failures: list[str] = []
    try:
        if path.suffix == ".whl":
            failures.extend(
                f"{item['marker']} in {path.name}:{item['file']}" for item in scan_zip(path)
            )
            with zipfile.ZipFile(path) as archive:
                failures.extend(_raw_privacy_markers(f"{path.name}:ZIP_COMMENT", archive.comment))
                members = archive.infolist()
                names = [member.filename for member in members]
                if len(names) != len(set(names)):
                    failures.append(f"duplicate wheel member names: {path.name}")
                for member in members:
                    name = member.filename
                    metadata = name.encode("utf-8") + member.comment + member.extra
                    failures.extend(
                        _raw_privacy_markers(f"{path.name}:{name}:ZIP_METADATA", metadata)
                    )
                    pure = PurePosixPath(name)
                    if (
                        pure.is_absolute()
                        or ".." in pure.parts
                        or "\\" in name
                        or "\x00" in name
                        or pure.as_posix() != name
                    ):
                        failures.append(f"unsafe wheel member path: {path.name}:{name}")
                    if member.is_dir():
                        continue
                    content = archive.read(member)
                    failures.extend(_raw_privacy_markers(f"{path.name}:{name}", content))
        else:
            with tarfile.open(path, "r:gz") as archive:
                members = archive.getmembers()
                names = [member.name for member in members]
                if len(names) != len(set(names)):
                    failures.append(f"duplicate source-archive member names: {path.name}")
                for member in members:
                    name = member.name
                    metadata_fields = [
                        member.name,
                        member.linkname,
                        member.uname,
                        member.gname,
                        *(f"{key}={value}" for key, value in member.pax_headers.items()),
                    ]
                    metadata = "\n".join(metadata_fields).encode("utf-8", errors="strict")
                    failures.extend(
                        _raw_privacy_markers(f"{path.name}:{name}:TAR_METADATA", metadata)
                    )
                    pure = PurePosixPath(name)
                    if (
                        pure.is_absolute()
                        or ".." in pure.parts
                        or "\\" in name
                        or "\x00" in name
                        or pure.as_posix() != name
                    ):
                        failures.append(f"unsafe source-archive member path: {path.name}:{name}")
                    if member.issym() or member.islnk():
                        failures.append(f"source archive contains a link: {path.name}:{name}")
                    if member.isdir():
                        continue
                    if not member.isfile():
                        failures.append(
                            f"source archive contains a special member: {path.name}:{name}"
                        )
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        failures.append(f"source archive member is unreadable: {path.name}:{name}")
                        continue
                    content = extracted.read()
                    nested_name = f"{path.name}:{name}"
                    failures.extend(_text_privacy_markers(nested_name, content))
                    failures.extend(_raw_privacy_markers(nested_name, content))
    except (OSError, tarfile.TarError, ValueError, zipfile.BadZipFile) as error:
        failures.append(
            f"distribution archive inspection failed: {path.name}:{type(error).__name__}"
        )
    return sorted(set(failures))


def collect_members(*, root: Path = ROOT, version: str | None = None) -> list[Path]:
    """Collect only tracked release files plus the exact generated-artifact allowlist."""

    selected_version = version or project_version(root)
    tracked = _tracked_paths(root)
    required_tracked = {
        *ROOT_FILES,
        *REQUIREMENT_FILES,
        *SUBMISSION_FILES,
        *set(ARTIFACTS).difference(POST_HEAD_GENERATED_ARTIFACTS),
    }
    missing_from_head = required_tracked.difference(tracked)
    if missing_from_head:
        raise RuntimeError(
            "required release files are not tracked by HEAD: " + _format_paths(missing_from_head)
        )

    generated = _explicit_generated_paths(selected_version)
    unexpected_untracked = _untracked_paths(root).difference(generated)
    if unexpected_untracked:
        raise RuntimeError(
            "unexpected untracked files must be committed or removed before packaging: "
            + _format_paths(unexpected_untracked)
        )

    relative_members = {relative for relative in tracked if _is_allowed_tracked(relative)}
    for relative in generated:
        _validate_regular_member(root, relative)
        relative_members.add(relative)
    members = [_validate_regular_member(root, relative) for relative in relative_members]
    return sorted(members, key=lambda item: item.relative_to(root).as_posix())


def _load(relative: str, *, root: Path = ROOT) -> dict[str, Any]:
    payload = json.loads((root / relative).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected JSON object: {relative}")
    return payload


def _worktree_failures(root: Path, version: str) -> list[str]:
    failures: list[str] = []
    changed = _tracked_changes(root)
    if changed:
        failures.append("tracked files differ from HEAD: " + _format_paths(changed))
    unexpected = _untracked_paths(root).difference(_explicit_generated_paths(version))
    if unexpected:
        failures.append("unexpected untracked files: " + _format_paths(unexpected))
    return failures


def _head_member_failures(members: list[Path], root: Path) -> list[str]:
    """Compare every tracked payload byte and executable bit directly with HEAD."""

    failures: list[str] = []
    indexed = _tracked_paths(root)
    head_entries: dict[str, tuple[str, str, str]] = {}
    for record in _run_git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not record:
            continue
        metadata, encoded_path = record.split(b"\t", 1)
        mode, object_type, oid = metadata.decode("ascii").split(" ")
        relative = encoded_path.decode("utf-8", errors="surrogateescape")
        head_entries[relative] = (mode, object_type, oid)
    for member in members:
        relative = member.relative_to(root).as_posix()
        head_entry = head_entries.get(relative)
        if head_entry is None:
            if relative in indexed:
                failures.append(f"tracked payload is absent from HEAD: {relative}")
            continue
        expected_mode, object_type, oid = head_entry
        if object_type != "blob":
            failures.append(f"tracked payload is not a blob in HEAD: {relative}")
            continue
        try:
            _validated_relative, content, local_mode = _snapshot_member(root, member)
            head_content = _run_git(root, "cat-file", "blob", oid)
        except (FileNotFoundError, OSError, RuntimeError, UnicodeError):
            failures.append(f"tracked payload could not be compared with HEAD: {relative}")
            continue
        if content != head_content:
            failures.append(f"tracked payload bytes do not match HEAD: {relative}")
        observed_mode = f"{_archive_mode_from_stat(local_mode):06o}"
        if expected_mode != observed_mode:
            failures.append(f"tracked payload mode does not match HEAD: {relative}")
    return failures


def _bound_file_failures(
    label: str,
    receipt: Any,
    expected_relative: str,
    root: Path,
) -> list[str]:
    if not isinstance(receipt, dict):
        return [f"{label} receipt is missing or malformed"]
    failures: list[str] = []
    if receipt.get("passed") is not True:
        failures.append(f"{label} receipt is not passed")
    if receipt.get("path") != expected_relative:
        failures.append(f"{label} receipt path is not the required delivery path")
    try:
        target = _validate_regular_member(root, expected_relative)
    except (FileNotFoundError, RuntimeError) as error:
        return [*failures, str(error)]
    if receipt.get("size_bytes") != target.stat().st_size:
        failures.append(f"{label} receipt size does not match the delivered file")
    if receipt.get("sha256") != _digest_file(target):
        failures.append(f"{label} receipt hash does not match the delivered file")
    return failures


def _delivery_failures(delivery: dict[str, Any], root: Path) -> list[str]:
    failures = validate_delivery_receipt(delivery, root)
    for label, relative in DELIVERY_ARTIFACTS.items():
        failures.extend(_bound_file_failures(label, delivery.get(label), relative, root))
    return failures


def _clean_archive_failures(
    clean: dict[str, Any],
    *,
    root: Path,
) -> list[str]:
    failures: list[str] = []
    if not clean_replay_current(clean, root):
        failures.append("clean replay does not satisfy the current release integrity contract")

    version = project_version(root)
    for relative in sorted(_expected_archive_paths(version)):
        name = PurePosixPath(relative).name
        try:
            archive = _validate_regular_member(root, relative)
        except (FileNotFoundError, RuntimeError) as error:
            failures.append(str(error))
            continue
        try:
            safe, _member_count = archive_members_safe(archive)
        except (OSError, ValueError, zipfile.BadZipFile):
            safe = False
        if not safe:
            failures.append(f"clean replay archive failed live path/integrity validation: {name}")
        nested_failures = _distribution_archive_failures(archive)
        failures.extend(
            f"clean replay archive content failed validation: {failure}"
            for failure in nested_failures
        )
    return failures


def _clean_ci_artifact_failures(
    public_ci: dict[str, Any],
    *,
    root: Path,
) -> list[str]:
    """Bind GitHub's artifact ZIP to its receipt and the final package bytes."""

    failures: list[str] = []
    try:
        zip_path = _validate_regular_member(root, CLEAN_ARTIFACT_ZIP_PATH)
        observed = inspect_clean_release_artifact_zip(
            zip_path,
            version=project_version(root),
        )
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        return [f"clean-release CI artifact failed strict ZIP validation: {error}"]

    artifact = public_ci.get("clean_release_artifact")
    if not isinstance(artifact, dict):
        return ["public CI receipt does not bind the clean-release artifact"]
    claimed_zip = artifact.get("zip")
    if claimed_zip != observed:
        failures.append("public CI receipt does not match the downloaded clean-release ZIP")
    metadata = artifact.get("metadata")
    github_digest = metadata.get("digest") if isinstance(metadata, dict) else None
    if github_digest != f"sha256:{observed['sha256']}":
        failures.append("downloaded clean-release ZIP does not match GitHub artifact digest")

    try:
        privacy = scan_zip(zip_path)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        failures.append(f"clean-release CI artifact privacy scan failed: {type(error).__name__}")
        privacy = []
    failures.extend(
        f"clean-release CI artifact privacy violation: {item['marker']} in {item['file']}"
        for item in privacy
    )

    expected = expected_clean_artifact_members(project_version(root))
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for relative in expected:
                info = archive.getinfo(relative)
                content = archive.read(info)
                metadata_bytes = (
                    info.filename.encode("utf-8", errors="strict") + info.comment + info.extra
                )
                failures.extend(
                    f"clean-release CI artifact raw privacy violation: {failure}"
                    for failure in _raw_privacy_markers(
                        f"{CLEAN_ARTIFACT_ZIP_PATH}:{relative}:ZIP_METADATA",
                        metadata_bytes,
                    )
                )
                failures.extend(
                    f"clean-release CI artifact raw privacy violation: {failure}"
                    for failure in _raw_privacy_markers(
                        f"{CLEAN_ARTIFACT_ZIP_PATH}:{relative}",
                        content,
                    )
                )
                target = _validate_regular_member(root, relative)
                if target.read_bytes() != content:
                    failures.append(
                        "clean-release CI artifact member is not byte-exact with the final "
                        f"package file: {relative}"
                    )
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        failures.append(f"clean-release CI artifact byte binding failed: {type(error).__name__}")
    return sorted(set(failures))


def _public_ci_failures(receipt: dict[str, Any], commit: str) -> list[str]:
    return validate_public_ci_receipt(receipt, commit, live=True)


def _preflight(
    members: list[Path],
    *,
    root: Path = ROOT,
    commit: str | None = None,
) -> dict[str, Any]:
    selected_commit = commit or _head_commit(root)
    version = project_version(root)
    source_digest = source_tree_digest(root)
    gate = _load("artifacts/champion-gate.json", root=root)
    contract = _load("competition/champion-contract.json", root=root)
    evidence = _load("artifacts/champion-evidence.json", root=root)
    clean = _load("artifacts/clean-replay.json", root=root)
    agentteams = _load("artifacts/agentteams-live-evidence.json", root=root)
    delivery = _load("artifacts/delivery-qa.json", root=root)
    public_ci = _load("artifacts/public-ci.json", root=root)

    failures = [*_worktree_failures(root, version), *_head_member_failures(members, root)]
    if version != "0.2.0":
        failures.append("GOAI champion package must use project version 0.2.0")
    try:
        recomputed_gate_failures = [
            *validate_manifest_integrity(evidence, root),
            *validate_runtime_semantics(root),
            *evaluate(contract, evidence),
        ]
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        recomputed_gate_failures = [f"champion evidence validation error: {type(error).__name__}"]
    if recomputed_gate_failures:
        failures.append("champion evidence failed live manifest/threshold validation")
    if gate.get("status") != "ready" or gate.get("failures") != []:
        failures.append("stored champion gate is not ready")
    if gate.get("failures") != recomputed_gate_failures:
        failures.append("stored champion gate does not match live evaluation")
    if not live_evidence_is_valid(agentteams):
        failures.append("official AgentTeams evidence failed strict live validation")
    failures.extend(
        _clean_archive_failures(
            clean,
            root=root,
        )
    )
    failures.extend(_delivery_failures(delivery, root))
    failures.extend(_public_ci_failures(public_ci, selected_commit))
    failures.extend(_clean_ci_artifact_failures(public_ci, root=root))
    privacy_failures = scan_paths(members, root=root)
    raw_privacy_failures: list[str] = []
    for member in members:
        relative, content, _mode = _snapshot_member(root, member)
        raw_privacy_failures.extend(_raw_privacy_markers(relative, content))
    if privacy_failures:
        failures.append("public-release privacy/credential scan failed")
    if raw_privacy_failures:
        failures.append("public-release raw-byte privacy/credential scan failed")
    if failures:
        raise RuntimeError("; ".join(failures))
    return {
        "version": version,
        "source_commit": selected_commit,
        "source_tree_digest": source_digest,
        "public_ci_url": public_ci["html_url"],
        "privacy_scan": {"passed": True, "violations": []},
    }


def _archive_mode(member: Path) -> int:
    permissions = stat.S_IMODE(member.lstat().st_mode)
    return 0o100755 if permissions & 0o111 else 0o100644


def _archive_mode_from_stat(mode: int) -> int:
    permissions = stat.S_IMODE(mode)
    return 0o100755 if permissions & 0o111 else 0o100644


def _verify_final_archive(
    archive_path: Path,
    *,
    records: list[dict[str, Any]],
    manifest_bytes: bytes,
) -> list[str]:
    """Re-open the finished ZIP and bind names, bytes, modes, CRC, paths and privacy."""

    failures: list[str] = []
    failures.extend(f"{item['marker']}: {item['file']}" for item in scan_zip(archive_path))
    expected_names = [str(record["path"]) for record in records]
    expected_all = {*expected_names, "SUBMISSION_MANIFEST.json"}
    if len(expected_names) != len(set(expected_names)):
        failures.append("frozen payload manifest contains duplicate paths")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            if archive.comment:
                failures.append("ZIP archive comment must be empty")
            infos = archive.infolist()
            names = [info.filename for info in infos]
            for name in names:
                pure = PurePosixPath(name)
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or "\\" in name
                    or "\x00" in name
                    or pure.as_posix() != name
                ):
                    failures.append(f"ZIP contains an unsafe member path: {name!r}")
            if len(names) != len(set(names)):
                failures.append("ZIP contains duplicate member names")
            if set(names) != expected_all or len(names) != len(expected_all):
                failures.append("ZIP member set does not match the frozen payload manifest")
            info_by_name = {info.filename: info for info in infos}
            for record in records:
                name = str(record["path"])
                info = info_by_name.get(name)
                if info is None:
                    continue
                if info.is_dir():
                    failures.append(f"ZIP payload member is unexpectedly a directory: {name}")
                    continue
                if info.comment or info.extra:
                    failures.append(f"ZIP payload member has unexpected metadata: {name}")
                content = archive.read(info)
                if len(content) != record["size_bytes"]:
                    failures.append(f"ZIP payload size mismatch: {name}")
                if _digest_bytes(content) != record["sha256"]:
                    failures.append(f"ZIP payload hash mismatch: {name}")
                archived_mode = info.external_attr >> 16
                if stat.S_IFMT(archived_mode) != stat.S_IFREG:
                    failures.append(f"ZIP payload member is not a regular file: {name}")
                if stat.S_IMODE(archived_mode) != int(str(record["mode"]), 8):
                    failures.append(f"ZIP payload mode mismatch: {name}")
            manifest_info = info_by_name.get("SUBMISSION_MANIFEST.json")
            if manifest_info is not None:
                if manifest_info.comment or manifest_info.extra:
                    failures.append("ZIP submission manifest has unexpected metadata")
                manifest_mode = manifest_info.external_attr >> 16
                if (
                    stat.S_IFMT(manifest_mode) != stat.S_IFREG
                    or stat.S_IMODE(manifest_mode) != 0o644
                ):
                    failures.append("ZIP submission manifest mode/type is invalid")
                if archive.read(manifest_info) != manifest_bytes:
                    failures.append("ZIP submission manifest bytes changed after construction")
            if archive.testzip() is not None:
                failures.append("ZIP CRC verification failed")
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        failures.append(f"ZIP verification error: {type(error).__name__}")
    return failures


def build(output: Path, *, root: Path = ROOT) -> dict[str, Any]:
    version = project_version(root)
    commit = _head_commit(root)
    members = collect_members(root=root, version=version)
    preflight = _preflight(members, root=root, commit=commit)
    member_data = [_snapshot_member(root, member) for member in members]

    # Detect any source/evidence drift between validation and the immutable byte snapshot.
    postflight = _preflight(members, root=root, commit=commit)
    if postflight != preflight:
        raise RuntimeError("submission inputs changed during packaging")
    if _head_commit(root) != commit:
        raise RuntimeError("HEAD changed during packaging")
    for relative, data, mode in member_data:
        current_relative, current_data, current_mode = _snapshot_member(root, root / relative)
        if (current_relative, current_data, stat.S_IMODE(current_mode)) != (
            relative,
            data,
            stat.S_IMODE(mode),
        ):
            raise RuntimeError(f"submission input changed during packaging: {relative}")

    records = [
        {
            "path": relative,
            "size_bytes": len(data),
            "sha256": _digest_bytes(data),
            "mode": f"{_archive_mode_from_stat(mode) & 0o777:04o}",
        }
        for relative, data, mode in member_data
    ]
    record_by_path = {record["path"]: record for record in records}
    manifest = {
        "schema_version": "2.0",
        "project": "RemedyFabric",
        "track": "GOAI 2026 Agent Infra",
        "version": preflight["version"],
        "source_commit": preflight["source_commit"],
        "source_tree_digest": preflight["source_tree_digest"],
        "public_ci": {
            "head_sha": preflight["source_commit"],
            "run_url": preflight["public_ci_url"],
        },
        "evidence_bindings": {
            relative: record_by_path[relative]["sha256"]
            for relative in (
                "artifacts/agentteams-live-evidence.json",
                "artifacts/champion-evidence.json",
                "artifacts/champion-gate.json",
                "artifacts/clean-replay.json",
                CLEAN_ARTIFACT_ZIP_PATH,
                "artifacts/delivery-qa.json",
                "artifacts/public-ci.json",
            )
        },
        "privacy_scan": preflight["privacy_scan"],
        "payload_file_count": len(records),
        "files": records,
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
        with zipfile.ZipFile(
            temporary_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for relative, data, mode in member_data:
                info = zipfile.ZipInfo(relative, (2026, 8, 12, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = _archive_mode_from_stat(mode) << 16
                archive.writestr(info, data)
            info = zipfile.ZipInfo("SUBMISSION_MANIFEST.json", (2026, 8, 12, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, manifest_bytes)
        archive_failures = _verify_final_archive(
            temporary_path,
            records=records,
            manifest_bytes=manifest_bytes,
        )
        if archive_failures:
            raise RuntimeError(f"archive public-release scan failed: {archive_failures}")
        temporary_path.replace(output)
        temporary_path = None
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return {
        "output": str(output),
        "sha256": _digest_file(output),
        "size_bytes": output.stat().st_size,
        "file_count": len(records) + 1,
        "version": preflight["version"],
        "source_commit": preflight["source_commit"],
        "source_tree_digest": preflight["source_tree_digest"],
        "public_ci_url": preflight["public_ci_url"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    print(json.dumps(build(output), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
