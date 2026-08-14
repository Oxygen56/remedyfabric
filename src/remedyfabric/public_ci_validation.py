"""Capture and validate one completed public GitHub Actions run.

The final-evidence job cannot truthfully certify its own success while it is
still running.  This module therefore only accepts a receipt captured *after*
the public workflow has completed, and independently re-reads the run and its
five jobs from GitHub before authorizing a release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import urllib.error
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

REPOSITORY = "Oxygen56/remedyfabric"
WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUIRED_JOBS = {
    "python (3.11)": "python-3.11",
    "python (3.13)": "python-3.13",
    "release-package": "release-package",
    "evidence-site": "evidence-site",
    "final-evidence": "final-evidence",
}
RECEIPT_JOB_ALIASES = frozenset(REQUIRED_JOBS.values())
RUN_URL_PATTERN = re.compile(
    r"https://github\.com/Oxygen56/remedyfabric/actions/runs/(?P<run_id>[1-9][0-9]*)"
)
CLEAN_ARTIFACT_ZIP_PATH = "artifacts/clean-release-ci.zip"
CLEAN_RECEIPT_MEMBER = "artifacts/clean-replay.json"
WHEEL_MEMBER_PATTERN = re.compile(
    r"dist/remedyfabric-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl"
)
SDIST_MEMBER_PATTERN = re.compile(r"dist/remedyfabric-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz")


def clean_artifact_name(head_sha: str) -> str:
    """Return the one artifact name permitted for a frozen source commit."""

    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise ValueError("frozen HEAD is invalid")
    return f"clean-release-{head_sha}"


def expected_clean_artifact_members(version: str) -> tuple[str, str, str]:
    """Return the exact three regular files carried by the clean CI artifact."""

    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("project version is invalid")
    return (
        CLEAN_RECEIPT_MEMBER,
        f"dist/remedyfabric-{version}-py3-none-any.whl",
        f"dist/remedyfabric-{version}.tar.gz",
    )


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_zip_member_name(name: str) -> bool:
    pure = PurePosixPath(name)
    try:
        name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return not (
        pure.is_absolute()
        or not pure.parts
        or ".." in pure.parts
        or "\\" in name
        or "\x00" in name
        or pure.as_posix() != name
    )


def _zip_member_is_regular(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    member_type = stat.S_IFMT(mode)
    # Some ZIP writers do not set a Unix file type.  Zero is safe for a
    # non-directory entry; explicit special types and symlinks are not.
    return not info.is_dir() and member_type in (0, stat.S_IFREG)


def inspect_clean_release_artifact_zip(
    path: Path,
    *,
    version: str | None = None,
) -> dict[str, Any]:
    """Inspect one raw GitHub artifact ZIP and freeze its exact payload bytes.

    GitHub's artifact ``size_in_bytes`` is service metadata and is deliberately
    not compared with the downloaded ZIP size recorded here.
    """

    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("clean-release artifact ZIP is missing") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError("clean-release artifact ZIP is not a regular file")

    try:
        with zipfile.ZipFile(path) as archive:
            if archive.comment:
                raise ValueError("clean-release artifact ZIP comment must be empty")
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ValueError("clean-release artifact ZIP contains duplicate paths")
            if not all(_safe_zip_member_name(name) for name in names):
                raise ValueError("clean-release artifact ZIP contains an unsafe path")
            if any(info.flag_bits & 0x1 for info in infos):
                raise ValueError("clean-release artifact ZIP contains an encrypted member")
            if archive.testzip() is not None:
                raise ValueError("clean-release artifact ZIP failed CRC validation")

            files = [info for info in infos if not info.is_dir()]
            if len(files) != 3 or not all(_zip_member_is_regular(info) for info in files):
                raise ValueError(
                    "clean-release artifact ZIP must contain exactly three regular files"
                )
            file_names = {info.filename for info in files}
            wheel_matches = [WHEEL_MEMBER_PATTERN.fullmatch(name) for name in sorted(file_names)]
            wheel_versions = [match.group("version") for match in wheel_matches if match]
            sdist_matches = [SDIST_MEMBER_PATTERN.fullmatch(name) for name in sorted(file_names)]
            sdist_versions = [match.group("version") for match in sdist_matches if match]
            if (
                CLEAN_RECEIPT_MEMBER not in file_names
                or len(wheel_versions) != 1
                or len(sdist_versions) != 1
                or wheel_versions[0] != sdist_versions[0]
            ):
                raise ValueError(
                    "clean-release artifact ZIP does not contain the receipt, wheel, and sdist"
                )
            observed_version = wheel_versions[0]
            if version is not None and observed_version != version:
                raise ValueError("clean-release artifact ZIP project version does not match")
            expected = set(expected_clean_artifact_members(observed_version))
            if file_names != expected:
                raise ValueError("clean-release artifact ZIP member set is not exact")

            allowed_directories = {
                parent for name in expected for parent in (f"{PurePosixPath(name).parts[0]}/",)
            }
            directory_names = {info.filename for info in infos if info.is_dir()}
            if not directory_names.issubset(allowed_directories):
                raise ValueError("clean-release artifact ZIP contains an unexpected directory")
            member_records: dict[str, dict[str, Any]] = {}
            for info in sorted(files, key=lambda item: item.filename):
                digest = hashlib.sha256()
                observed_size = 0
                with archive.open(info, "r") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        observed_size += len(chunk)
                        digest.update(chunk)
                if observed_size != info.file_size:
                    raise ValueError("clean-release artifact ZIP member size changed while reading")
                member_records[info.filename] = {
                    "sha256": digest.hexdigest(),
                    "size_bytes": observed_size,
                }
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ValueError(
            f"clean-release artifact ZIP inspection failed: {type(error).__name__}"
        ) from error

    return {
        "path": CLEAN_ARTIFACT_ZIP_PATH,
        "sha256": _digest_file(path),
        "size_bytes": metadata.st_size,
        "members": member_records,
    }


def _get_json(url: str, timeout: int = 20) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "remedyfabric-gate",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise TypeError("GitHub response is not an object")
    return payload


def _run_id(run_url: object) -> int | None:
    match = RUN_URL_PATTERN.fullmatch(str(run_url))
    return int(match.group("run_id")) if match else None


def _live_payloads(
    run_id: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    base = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
    return (
        _get_json(base),
        _get_json(base + "/jobs?filter=latest&per_page=100"),
        _get_json(base + "/artifacts?per_page=100"),
    )


def _job_records(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    jobs = payload.get("jobs")
    if not isinstance(jobs, Sequence) or isinstance(jobs, (str, bytes)):
        raise TypeError("GitHub jobs response is malformed")
    if not all(isinstance(job, Mapping) for job in jobs):
        raise TypeError("GitHub job record is malformed")
    return list(jobs)


def _artifact_records(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
        raise TypeError("GitHub artifacts response is malformed")
    if not all(isinstance(artifact, Mapping) for artifact in artifacts):
        raise TypeError("GitHub artifact record is malformed")
    return list(artifacts)


def _artifact_metadata(
    artifact: Mapping[str, Any],
    *,
    run_id: int,
    head_sha: str,
) -> dict[str, Any]:
    artifact_id = artifact.get("id")
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, Mapping):
        workflow_run = {}
    expected_download_url = (
        f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"
    )
    if not (
        isinstance(artifact_id, int)
        and not isinstance(artifact_id, bool)
        and artifact_id > 0
        and artifact.get("name") == clean_artifact_name(head_sha)
        and artifact.get("expired") is False
        and isinstance(artifact.get("size_in_bytes"), int)
        and not isinstance(artifact.get("size_in_bytes"), bool)
        and artifact.get("size_in_bytes", -1) >= 0
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(artifact.get("digest", "")))
        and artifact.get("archive_download_url") == expected_download_url
        and workflow_run.get("id") == run_id
        and workflow_run.get("head_sha") == head_sha
    ):
        raise ValueError("public CI clean-release artifact metadata is invalid")
    return {
        "id": artifact_id,
        "name": artifact["name"],
        "size_in_bytes": artifact["size_in_bytes"],
        "digest": artifact["digest"],
        "expired": False,
        "url": artifact.get("url"),
        "archive_download_url": artifact["archive_download_url"],
        "created_at": artifact.get("created_at"),
        "updated_at": artifact.get("updated_at"),
        "expires_at": artifact.get("expires_at"),
        "workflow_run": {"id": run_id, "head_sha": head_sha},
    }


def _select_clean_artifact_metadata(
    payload: Mapping[str, Any],
    *,
    run_id: int,
    head_sha: str,
) -> dict[str, Any]:
    artifacts = _artifact_records(payload)
    total_count = payload.get("total_count")
    if (
        not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count != len(artifacts)
    ):
        raise ValueError("public CI artifacts response is incomplete")
    expected_name = clean_artifact_name(head_sha)
    matches = [artifact for artifact in artifacts if artifact.get("name") == expected_name]
    if len(matches) != 1:
        raise ValueError("public CI run must contain exactly one clean-release artifact")
    return _artifact_metadata(matches[0], run_id=run_id, head_sha=head_sha)


def _zip_receipt_shape_failures(zip_receipt: object) -> list[str]:
    if not isinstance(zip_receipt, Mapping):
        return ["public CI clean-release ZIP receipt is missing or malformed"]
    failures: list[str] = []
    members = zip_receipt.get("members")
    if not (
        zip_receipt.get("path") == CLEAN_ARTIFACT_ZIP_PATH
        and re.fullmatch(r"[0-9a-f]{64}", str(zip_receipt.get("sha256", "")))
        and isinstance(zip_receipt.get("size_bytes"), int)
        and not isinstance(zip_receipt.get("size_bytes"), bool)
        and zip_receipt.get("size_bytes", -1) >= 0
        and isinstance(members, Mapping)
    ):
        return ["public CI clean-release ZIP receipt is invalid"]
    names = {str(name) for name in members}
    wheel_versions = [
        match.group("version")
        for name in names
        if (match := WHEEL_MEMBER_PATTERN.fullmatch(name)) is not None
    ]
    sdist_versions = [
        match.group("version")
        for name in names
        if (match := SDIST_MEMBER_PATTERN.fullmatch(name)) is not None
    ]
    if (
        CLEAN_RECEIPT_MEMBER not in names
        or len(names) != 3
        or len(wheel_versions) != 1
        or len(sdist_versions) != 1
        or wheel_versions[0] != sdist_versions[0]
        or names != set(expected_clean_artifact_members(wheel_versions[0]))
    ):
        failures.append("public CI clean-release ZIP member set is invalid")
        return failures
    for name, record in members.items():
        if not (
            isinstance(name, str)
            and isinstance(record, Mapping)
            and set(record) == {"sha256", "size_bytes"}
            and re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))
            and isinstance(record.get("size_bytes"), int)
            and not isinstance(record.get("size_bytes"), bool)
            and record.get("size_bytes", -1) >= 0
        ):
            failures.append("public CI clean-release ZIP member receipt is invalid")
            break
    return failures


def _validate_live_payloads(
    *,
    receipt: Mapping[str, Any],
    head_sha: str,
    run_id: int,
    run: Mapping[str, Any],
    jobs_payload: Mapping[str, Any],
    artifacts_payload: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    repository = run.get("repository")
    if not isinstance(repository, Mapping):
        repository = {}
    if not (
        run.get("id") == run_id
        and repository.get("full_name") == REPOSITORY
        and run.get("head_sha") == head_sha
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("path") == WORKFLOW_PATH
        and run.get("html_url") == receipt.get("html_url")
        and run.get("run_attempt") == receipt.get("run_attempt")
    ):
        failures.append("public CI live run metadata does not match the frozen source")

    try:
        jobs = _job_records(jobs_payload)
    except TypeError:
        return [*failures, "public CI live jobs response is malformed"]
    observed_names = [str(job.get("name", "")) for job in jobs]
    if (
        jobs_payload.get("total_count") != len(REQUIRED_JOBS)
        or len(jobs) != len(REQUIRED_JOBS)
        or set(observed_names) != set(REQUIRED_JOBS)
    ):
        failures.append("public CI live run does not contain exactly the five required jobs")
    if len(observed_names) != len(set(observed_names)):
        failures.append("public CI live run contains duplicate required job names")
    for name in REQUIRED_JOBS:
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) != 1 or not (
            matches[0].get("status") == "completed" and matches[0].get("conclusion") == "success"
        ):
            failures.append(f"public CI live job is not completed and successful: {name}")
    try:
        live_artifact = _select_clean_artifact_metadata(
            artifacts_payload,
            run_id=run_id,
            head_sha=head_sha,
        )
    except (TypeError, ValueError) as error:
        failures.append(str(error))
    else:
        claimed_artifact = receipt.get("clean_release_artifact")
        claimed_metadata = (
            claimed_artifact.get("metadata") if isinstance(claimed_artifact, Mapping) else None
        )
        if claimed_metadata != live_artifact:
            failures.append("public CI live clean-release artifact metadata changed")
    return failures


def validate_public_ci_receipt(
    receipt: Mapping[str, Any] | None,
    head_sha: str,
    *,
    live: bool,
) -> list[str]:
    """Validate receipt shape and, for final release use, GitHub's live state."""

    if not receipt:
        return ["public CI receipt is missing"]
    failures: list[str] = []
    run_id = _run_id(receipt.get("html_url"))
    claimed_jobs = receipt.get("jobs")
    if not (
        receipt.get("schema_version") == "1.1"
        and receipt.get("repository") == REPOSITORY
        and receipt.get("workflow_path") == WORKFLOW_PATH
        and receipt.get("head_sha") == head_sha
        and re.fullmatch(r"[0-9a-f]{40}", head_sha)
        and receipt.get("status") == "completed"
        and receipt.get("conclusion") == "success"
        and isinstance(receipt.get("run_attempt"), int)
        and not isinstance(receipt.get("run_attempt"), bool)
        and receipt.get("run_attempt", 0) >= 1
        and run_id is not None
        and receipt.get("run_id") == run_id
        and re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("live_run_payload_sha256", "")))
        and re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("live_jobs_payload_sha256", "")))
        and re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("live_artifacts_payload_sha256", "")))
    ):
        failures.append("public CI receipt header is invalid")
    if not (
        isinstance(claimed_jobs, Mapping)
        and set(claimed_jobs) == RECEIPT_JOB_ALIASES
        and all(claimed_jobs.get(alias) == "success" for alias in RECEIPT_JOB_ALIASES)
    ):
        failures.append("public CI receipt does not claim exactly five required successful jobs")
    claimed_artifact = receipt.get("clean_release_artifact")
    if not (
        isinstance(claimed_artifact, Mapping)
        and set(claimed_artifact) == {"metadata", "zip"}
        and isinstance(claimed_artifact.get("metadata"), Mapping)
        and claimed_artifact["metadata"].get("name")
        == (clean_artifact_name(head_sha) if re.fullmatch(r"[0-9a-f]{40}", head_sha) else None)
    ):
        failures.append("public CI clean-release artifact receipt is invalid")
    else:
        try:
            artifact_metadata = _artifact_metadata(
                claimed_artifact["metadata"],
                run_id=run_id or -1,
                head_sha=head_sha,
            )
        except (TypeError, ValueError):
            failures.append("public CI clean-release artifact receipt is invalid")
        else:
            if artifact_metadata != claimed_artifact["metadata"]:
                failures.append("public CI clean-release artifact receipt is not canonical")
        failures.extend(_zip_receipt_shape_failures(claimed_artifact.get("zip")))
        metadata_digest = str(claimed_artifact["metadata"].get("digest", ""))
        zip_receipt = claimed_artifact.get("zip")
        zip_digest = zip_receipt.get("sha256") if isinstance(zip_receipt, Mapping) else None
        if metadata_digest != f"sha256:{zip_digest}":
            failures.append(
                "public CI clean-release ZIP digest does not match GitHub artifact digest"
            )
    if not live or run_id is None or failures:
        return failures
    try:
        run, jobs, artifacts = _live_payloads(run_id)
    except (OSError, TypeError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as error:
        return [*failures, f"public CI live verification failed: {type(error).__name__}"]
    if (
        receipt.get("live_run_payload_sha256")
        != hashlib.sha256(
            json.dumps(run, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    ):
        failures.append("public CI live run payload digest changed")
    if (
        receipt.get("live_jobs_payload_sha256")
        != hashlib.sha256(
            json.dumps(jobs, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    ):
        failures.append("public CI live jobs payload digest changed")
    if (
        receipt.get("live_artifacts_payload_sha256")
        != hashlib.sha256(
            json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    ):
        failures.append("public CI live artifacts payload digest changed")
    return [
        *failures,
        *_validate_live_payloads(
            receipt=receipt,
            head_sha=head_sha,
            run_id=run_id,
            run=run,
            jobs_payload=jobs,
            artifacts_payload=artifacts,
        ),
    ]


def capture_public_ci_receipt(
    run_url: str,
    head_sha: str,
    artifact_zip: Path,
) -> dict[str, Any]:
    """Fetch a completed run and return a final receipt, or fail closed."""

    run_id = _run_id(run_url)
    if run_id is None or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("run URL or frozen HEAD is invalid")
    run, jobs_payload, artifacts_payload = _live_payloads(run_id)
    run_attempt = run.get("run_attempt")
    if not isinstance(run_attempt, int) or isinstance(run_attempt, bool) or run_attempt < 1:
        raise TypeError("GitHub run attempt is missing or malformed")
    clean_artifact_metadata = _select_clean_artifact_metadata(
        artifacts_payload,
        run_id=run_id,
        head_sha=head_sha,
    )
    clean_artifact_zip = inspect_clean_release_artifact_zip(artifact_zip)
    if clean_artifact_metadata["digest"] != f"sha256:{clean_artifact_zip['sha256']}":
        raise RuntimeError(
            "downloaded clean-release ZIP digest does not match GitHub artifact metadata"
        )
    receipt: dict[str, Any] = {
        "schema_version": "1.1",
        "repository": REPOSITORY,
        "workflow_path": WORKFLOW_PATH,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": "success",
        "html_url": run_url,
        "jobs": {alias: "success" for alias in sorted(RECEIPT_JOB_ALIASES)},
        "captured_from_github_updated_at": run.get("updated_at"),
        "live_run_payload_sha256": hashlib.sha256(
            json.dumps(run, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "live_jobs_payload_sha256": hashlib.sha256(
            json.dumps(jobs_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "live_artifacts_payload_sha256": hashlib.sha256(
            json.dumps(artifacts_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "clean_release_artifact": {
            "metadata": clean_artifact_metadata,
            "zip": clean_artifact_zip,
        },
        "claim_boundary": (
            "Captured from the public GitHub REST API only after this exact workflow run "
            "completed; it covers the frozen HEAD, five named CI jobs, exact artifact metadata, "
            "and the separately hashed downloaded ZIP bytes. GitHub size_in_bytes is service "
            "metadata and is not asserted equal to the downloaded ZIP size; this is not "
            "deployment-use evidence."
        ),
    }
    failures = _validate_live_payloads(
        receipt=receipt,
        head_sha=head_sha,
        run_id=run_id,
        run=run,
        jobs_payload=jobs_payload,
        artifacts_payload=artifacts_payload,
    )
    if failures:
        raise RuntimeError("; ".join(failures))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument(
        "--artifact-zip",
        required=True,
        type=Path,
        help="Raw GitHub artifact ZIP downloaded for clean-release-<HEAD>.",
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/public-ci.json"))
    args = parser.parse_args()
    receipt = capture_public_ci_receipt(args.run_url, args.head_sha, args.artifact_zip)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "run_url": args.run_url}, indent=2))
    return 0


__all__ = [
    "CLEAN_ARTIFACT_ZIP_PATH",
    "CLEAN_RECEIPT_MEMBER",
    "RECEIPT_JOB_ALIASES",
    "REPOSITORY",
    "REQUIRED_JOBS",
    "WORKFLOW_PATH",
    "capture_public_ci_receipt",
    "clean_artifact_name",
    "expected_clean_artifact_members",
    "inspect_clean_release_artifact_zip",
    "validate_public_ci_receipt",
]


if __name__ == "__main__":
    raise SystemExit(main())
