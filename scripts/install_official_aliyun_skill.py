#!/usr/bin/env python3
"""Fetch and verify one pinned Alibaba Cloud official Skill for AgentTeams.

The script installs only package files.  It never reads Alibaba Cloud
credentials and never invokes a cloud API.
"""

from __future__ import annotations

import argparse
import io
import json
import tarfile
import tempfile
import urllib.request
from hashlib import sha256
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "agentteams" / "official-alibaba-cloud-skill.lock.json"


def digest_bytes(content: bytes) -> str:
    return sha256(content).hexdigest()


def aggregate_digest(manifest: dict[str, str]) -> str:
    lines = "".join(f"{digest}  {path}\n" for path, digest in sorted(manifest.items()))
    return digest_bytes(lines.encode("utf-8"))


def verify_directory(directory: Path, expected: dict[str, str]) -> None:
    observed: dict[str, str] = {}
    for relative, expected_digest in expected.items():
        path = directory / relative
        if not path.is_file():
            raise RuntimeError(f"official Skill file is missing: {relative}")
        observed_digest = sha256(path.read_bytes()).hexdigest()
        if observed_digest != expected_digest:
            raise RuntimeError(f"official Skill digest mismatch: {relative}")
        observed[relative] = observed_digest
    extra = sorted(
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.is_file() and str(path.relative_to(directory)) not in expected
    )
    if extra:
        raise RuntimeError(f"unexpected files in official Skill package: {extra}")
    if aggregate_digest(observed) != aggregate_digest(expected):
        raise RuntimeError("official Skill aggregate digest mismatch")


def fetch_package(lock: dict, timeout: int) -> bytes:
    commit = lock["commit"]
    repository = lock["repository"].removesuffix(".git")
    url = f"{repository}/archive/{commit}.tar.gz"
    request = urllib.request.Request(url, headers={"User-Agent": "RemedyFabric/0.2"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"official package download failed: HTTP {response.status}")
        return response.read()


def extract_verified(content: bytes, staging: Path, lock: dict) -> None:
    commit = lock["commit"]
    source_path = PurePosixPath(lock["skill"]["path"])
    expected: dict[str, str] = lock["skill"]["files"]
    archive_prefix = PurePosixPath(f"alibabacloud-aiops-skills-{commit}") / source_path
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            try:
                relative = member_path.relative_to(archive_prefix)
            except ValueError:
                continue
            if str(relative) == ".":
                continue
            relative_text = str(relative)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"unsafe archive path: {relative_text}")
            if member.issym() or member.islnk():
                raise RuntimeError(
                    f"links are forbidden in official Skill package: {relative_text}"
                )
            if member.isdir():
                continue
            if not member.isfile() or relative_text not in expected:
                raise RuntimeError(f"unexpected package member: {relative_text}")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read package member: {relative_text}")
            payload = source.read()
            if digest_bytes(payload) != expected[relative_text]:
                raise RuntimeError(f"downloaded package digest mismatch: {relative_text}")
            destination = staging / relative_text
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            seen.add(relative_text)
    missing = sorted(set(expected) - seen)
    if missing:
        raise RuntimeError(f"official package is incomplete: {missing}")
    verify_directory(staging, expected)


def install(workspace: Path, timeout: int) -> dict:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    name = lock["skill"]["name"]
    expected: dict[str, str] = lock["skill"]["files"]
    destination = workspace.resolve() / "worker-skills" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify_directory(destination, expected)
        mode = "verified-existing"
    else:
        content = fetch_package(lock, timeout)
        with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=destination.parent) as temp:
            staging = Path(temp) / name
            staging.mkdir()
            extract_verified(content, staging, lock)
            staging.rename(destination)
        mode = "downloaded-and-verified"
    return {
        "status": "ready",
        "mode": mode,
        "publisher": lock["publisher"],
        "repository": lock["repository"],
        "commit": lock["commit"],
        "skill": name,
        "destination": str(destination),
        "file_count": len(expected),
        "aggregate_sha256": lock["skill"]["aggregate_sha256"],
        "cloud_credentials_read": False,
        "cloud_api_invoked": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    result = install(args.workspace, args.timeout)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
