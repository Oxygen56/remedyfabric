#!/usr/bin/env python3
"""Build release archives, inspect them, and replay the suite in a clean container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from remedyfabric.release_integrity import (
    CHAMPION_VERSION,
    CLEAN_REPLAY_BUILD_COMMAND,
    CLEAN_REPLAY_EXTERNAL_TESTS,
    CLEAN_REPLAY_MIN_TESTS,
    EXCLUDED_PARTS,
    SOURCE_DIRECTORIES,
    SOURCE_FILES,
    project_version,
    source_tree_digest,
)

ROOT = Path(__file__).resolve().parents[1]


def _public_text(value: str) -> str:
    """Remove host-specific home and repository paths from retained command output."""

    rendered = value.replace(str(ROOT), "<project-root>")
    rendered = rendered.replace(str(Path.home()), "<home>")
    return re.sub(r"/Users/[^/\s]+", "<home>", rendered)


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _member_is_safe(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def archive_members_safe(path: Path) -> tuple[bool, int]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            integrity_ok = archive.testzip() is None
            links_absent = all(
                stat.S_IFMT(member.external_attr >> 16) != stat.S_IFLNK for member in members
            )
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            links_absent = all(not member.issym() and not member.islnk() for member in members)
            integrity_ok = True
            for member in members:
                if member.isfile():
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        integrity_ok = False
                        break
                    while extracted.read(1024 * 1024):
                        pass
    return (
        all(_member_is_safe(name) for name in names) and links_absent and integrity_ok,
        len(names),
    )


def _run(command: tuple[str, ...], *, cwd: Path = ROOT, timeout: int = 300) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": list(command),
            "returncode": completed.returncode,
            "stdout": _public_text(completed.stdout[-20_000:]),
            "stderr": _public_text(completed.stderr[-20_000:]),
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "returncode": 124,
            "stdout": (
                _public_text((error.stdout or "")[-20_000:])
                if isinstance(error.stdout, str)
                else ""
            ),
            "stderr": (
                _public_text((error.stderr or "")[-20_000:])
                if isinstance(error.stderr, str)
                else ""
            ),
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "timed_out": True,
        }


def _docker_command(context: str, *arguments: str) -> tuple[str, ...]:
    command = ("docker",)
    if context:
        command += ("--context", context)
    return command + arguments


def _base_image(docker_context: str) -> dict[str, str]:
    inspected = _run(
        _docker_command(
            docker_context,
            "image",
            "inspect",
            "python:3.12-slim",
            "--format",
            "{{json .RepoDigests}}|{{.Os}}/{{.Architecture}}|{{.Id}}",
        ),
        timeout=30,
    )
    if inspected["returncode"] != 0:
        raise RuntimeError("python:3.12-slim must exist locally before offline replay")
    repo_json, platform, image_id = inspected["stdout"].strip().split("|", 2)
    repo_digests = json.loads(repo_json)
    matching = sorted(
        digest for digest in repo_digests if re.fullmatch(r"python@sha256:[0-9a-f]{64}", digest)
    )
    if len(matching) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise RuntimeError("python:3.12-slim must resolve to one immutable local RepoDigest")
    return {
        "tag": "python:3.12-slim",
        "resolved_reference": matching[0],
        "platform": platform,
        "image_id": image_id,
    }


def _runner_source(nonce: str) -> str:
    excluded = json.dumps(CLEAN_REPLAY_EXTERNAL_TESTS, sort_keys=True)
    return f"""from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from remedyfabric.benchmark import run_benchmark
from remedyfabric.evidence_validation import (
    validate_faultbench,
    validate_quorum_model,
    validate_resilient_matrix,
)
from remedyfabric.faultbench import run_faultbench
from remedyfabric.resilient import run_resilient_matrix

ROOT = Path("/project")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
EXCLUDED = {excluded}
NONCE = {nonce!r}


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


discovered = list(flatten(unittest.defaultTestLoader.discover("tests")))
by_id = {{test.id(): test for test in discovered}}
missing_exclusions = sorted(set(EXCLUDED).difference(by_id))
selected_ids = sorted(set(by_id).difference(EXCLUDED))
selected = [by_id[test_id] for test_id in selected_ids]
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
suite_receipt = {{
    "nonce": NONCE,
    "kind": "pure-python-offline",
    "discovered_tests": len(discovered),
    "executed_tests": result.testsRun,
    "skipped_tests": len(result.skipped),
    "selected_test_ids_sha256": hashlib.sha256(
        "\\n".join(selected_ids).encode("utf-8")
    ).hexdigest(),
    "excluded_external_tests": EXCLUDED,
    "missing_expected_exclusions": missing_exclusions,
    "passed": (
        result.wasSuccessful()
        and not missing_exclusions
        and result.testsRun == len(selected_ids)
        and result.testsRun >= {CLEAN_REPLAY_MIN_TESTS}
        and not result.skipped
    ),
}}
print("CLEAN_SUITE_RESULT=" + json.dumps(suite_receipt, sort_keys=True))
if not suite_receipt["passed"]:
    raise SystemExit(1)

with tempfile.TemporaryDirectory(prefix="remedyfabric-clean-semantic-") as temporary:
    temporary_path = Path(temporary)
    resilient = run_resilient_matrix().payload
    (temporary_path / "resilient.json").write_text(json.dumps(resilient))
    faultbench = run_faultbench(
        ROOT / "faultbench/cases.json", temporary_path / "faultbench.json"
    )
    quorum_command = [
        sys.executable,
        str(ROOT / "scripts/check_quorum_model.py"),
        "--output",
        str(temporary_path / "quorum.json"),
    ]
    quorum_completed = subprocess.run(
        quorum_command, cwd=ROOT, check=False, text=True, capture_output=True, timeout=180
    )
    if quorum_completed.returncode != 0:
        print(quorum_completed.stdout)
        print(quorum_completed.stderr, file=sys.stderr)
        raise SystemExit(quorum_completed.returncode)
    quorum = json.loads((temporary_path / "quorum.json").read_text())
    benchmark = run_benchmark(temporary_path / "benchmark.json")

resilient_failures = validate_resilient_matrix(resilient)
quorum_failures = validate_quorum_model(quorum)
faultbench_failures = validate_faultbench(faultbench, ROOT / "faultbench/cases.json")
failures = [*resilient_failures, *quorum_failures, *faultbench_failures]
profiles = {{profile["profile"]: profile for profile in benchmark["profiles"]}}
full = profiles.get("full", {{}})
benchmark_ok = (
    benchmark.get("scenario_count") == 8
    and set(profiles) == {{
        "full", "single-agent", "no-verifier", "no-governor", "no-rollback"
    }}
    and full.get("recovery_success_rate") == 1.0
    and full.get("safety_violation_rate") == 0.0
    and full.get("rollback_success_rate") == 1.0
    and full.get("ledger_integrity_rate") == 1.0
)
semantic = {{
    "remedybench": benchmark_ok,
    "resilient_matrix": not resilient_failures,
    "quorum_model": not quorum_failures,
    "faultbench": not faultbench_failures,
}}
semantic_receipt = {{
    "nonce": NONCE,
    "passed": not failures and all(semantic.values()),
    "replays": semantic,
}}
print("CLEAN_SEMANTIC_RESULT=" + json.dumps(semantic_receipt, sort_keys=True))
if not semantic_receipt["passed"]:
    print(json.dumps({{"failures": failures}}, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
"""


def _receipt_marker(output: str, marker: str, nonce: str) -> dict[str, Any] | None:
    matches = re.findall(rf"^{re.escape(marker)}=(\{{.*\}})$", output, flags=re.MULTILINE)
    if len(matches) != 1:
        return None
    try:
        payload = json.loads(matches[0])
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) and payload.get("nonce") == nonce else None


def _copy_inputs(context: Path, wheel: Path, nonce: str) -> None:
    (context / "dist").mkdir()
    shutil.copy2(wheel, context / "dist" / wheel.name)
    for directory in SOURCE_DIRECTORIES:
        source = ROOT / directory
        if source.exists():
            ignored = [*EXCLUDED_PARTS, "*.egg-info", "*.pyc", "*.pyo"]
            shutil.copytree(source, context / directory, ignore=shutil.ignore_patterns(*ignored))
    for relative in SOURCE_FILES:
        source = ROOT / relative
        if source.is_file():
            destination = context / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    artifacts = ROOT / "artifacts"
    shutil.copytree(
        artifacts,
        context / "artifacts",
        ignore=shutil.ignore_patterns(
            "champion-evidence.json",
            "champion-gate.json",
            "clean-replay.json",
            "public-ci.json",
            "*.mp4",
        ),
    )
    (context / "clean_replay_entrypoint.py").write_text(_runner_source(nonce), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/clean-replay.json"))
    parser.add_argument(
        "--docker-context",
        default=os.environ.get("DOCKER_CONTEXT", ""),
        help="Optional isolated Docker context; defaults to DOCKER_CONTEXT or the active context.",
    )
    args = parser.parse_args()
    output = ROOT / args.output if not args.output.is_absolute() else args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    version = project_version(ROOT)
    if version != CHAMPION_VERSION:
        raise RuntimeError(f"clean replay requires champion version {CHAMPION_VERSION}")
    source_digest = source_tree_digest(ROOT)

    build = _run(CLEAN_REPLAY_BUILD_COMMAND)
    source_tree_unchanged = source_tree_digest(ROOT) == source_digest
    expected_names = {
        f"remedyfabric-{version}-py3-none-any.whl",
        f"remedyfabric-{version}.tar.gz",
    }
    dist_members = sorted((ROOT / "dist").iterdir()) if build["returncode"] == 0 else []
    archives = [path for path in dist_members if path.is_file()]
    unexpected_dist_members = [
        path.name for path in dist_members if path.name not in expected_names
    ]
    exact_archives = {path.name: path for path in archives if path.name in expected_names}
    wheel = exact_archives.get(f"remedyfabric-{version}-py3-none-any.whl")
    archive_evidence = []
    for archive in archives:
        safe, member_count = archive_members_safe(archive)
        archive_evidence.append(
            {
                "name": archive.name,
                "sha256": _digest(archive),
                "size_bytes": archive.stat().st_size,
                "member_count": member_count,
                "member_paths_safe": safe,
            }
        )

    base_image: dict[str, str] = {}
    image_tag = f"remedyfabric-clean-replay:{int(time.time())}"
    image_build: dict[str, Any] = {"returncode": 1, "reason": "package build failed"}
    replay: dict[str, Any] = {"returncode": 1, "reason": "container image unavailable"}
    nonce = secrets.token_hex(16)
    if (
        wheel is not None
        and {path.name for path in archives} == expected_names
        and not unexpected_dist_members
        and all(item["member_paths_safe"] for item in archive_evidence)
    ):
        base_image = _base_image(args.docker_context)
        temp_root = ROOT / "tmp"
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="clean-replay-", dir=temp_root) as temp:
            context = Path(temp)
            _copy_inputs(context, wheel, nonce)
            dockerfile = (
                f"FROM {base_image['resolved_reference']}\n"
                f"COPY dist/{wheel.name} /tmp/{wheel.name}\n"
                "RUN python -m pip install --no-index --disable-pip-version-check "
                f"/tmp/{wheel.name} && rm /tmp/{wheel.name}\n"
                "WORKDIR /project\n"
                "COPY . /project\n"
                "COPY clean_replay_entrypoint.py /clean_replay_entrypoint.py\n"
                "ENV PYTHONDONTWRITEBYTECODE=1\n"
            )
            (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            image_build = _run(
                _docker_command(
                    args.docker_context,
                    "build",
                    "--network",
                    "none",
                    "--tag",
                    image_tag,
                    ".",
                ),
                cwd=context,
            )
            if image_build["returncode"] == 0:
                replay = _run(
                    _docker_command(
                        args.docker_context,
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
                        "--tmpfs",
                        "/tmp:rw,noexec,nosuid,nodev,size=256m",
                        image_tag,
                        "python",
                        "/clean_replay_entrypoint.py",
                    ),
                    timeout=900,
                )
        _run(
            _docker_command(args.docker_context, "image", "rm", "--force", image_tag),
            timeout=60,
        )

    suite_receipt = _receipt_marker(str(replay.get("stdout", "")), "CLEAN_SUITE_RESULT", nonce)
    semantic_receipt = _receipt_marker(
        str(replay.get("stdout", "")), "CLEAN_SEMANTIC_RESULT", nonce
    )
    tests_run = int(suite_receipt.get("executed_tests", 0)) if suite_receipt else 0
    skipped = int(suite_receipt.get("skipped_tests", -1)) if suite_receipt else -1
    semantic_replays = semantic_receipt.get("replays", {}) if semantic_receipt else {}
    semantic_evidence_validated = bool(semantic_receipt and semantic_receipt.get("passed") is True)
    passed = bool(
        build["returncode"] == 0
        and source_tree_unchanged
        and {path.name for path in archives} == expected_names
        and not unexpected_dist_members
        and len(archive_evidence) == 2
        and all(item["member_paths_safe"] for item in archive_evidence)
        and image_build.get("returncode") == 0
        and replay.get("returncode") == 0
        and suite_receipt
        and suite_receipt.get("passed") is True
        and tests_run >= CLEAN_REPLAY_MIN_TESTS
        and skipped == 0
        and semantic_evidence_validated
    )
    payload = {
        "schema_version": "1.0",
        "passed": passed,
        "project_version": version,
        "source_tree_digest": source_digest,
        "source_tree_unchanged_after_build": source_tree_unchanged,
        "package_build": build,
        "archives": archive_evidence,
        "unexpected_dist_members": unexpected_dist_members,
        "clean_environment": {
            "docker_context": args.docker_context or "active-default",
            "base_image": base_image,
            "host_package_build": (
                "uv build --offline --clear --no-create-gitignore --out-dir dist ."
            ),
            "container_image_build_network": "none",
            "runtime_network": "none",
            "rootfs_read_only": True,
            "image_build": image_build,
            "replay": replay,
            "tests_run": tests_run,
            "tests_skipped": skipped,
            "test_suite": suite_receipt or {},
            "semantic_evidence_validated": semantic_evidence_validated,
            "semantic_replays": semantic_replays,
            "external_runtime_boundaries": {
                "node_rust_micro_replays": (
                    "not executed in the Python-only clean container; rerun by CI final-evidence"
                ),
                "nested_docker_isolation": (
                    "not executed inside the clean container; rerun by CI final-evidence"
                ),
                "git_repository_fixtures": (
                    "not executed because the immutable clean image intentionally has no Git"
                ),
                "delivery_inspection": (
                    "not executed because the Python-only wheel intentionally excludes PDF/video "
                    "rendering dependencies; CI final-evidence validates the frozen delivery bytes"
                ),
            },
        },
        "claim_boundary": (
            "One source-digest-bound, Python-only clean Linux replay after building and binding "
            "the exact 0.2.0 wheel and sdist, with the wheel installed offline. The sdist is "
            "archive-inspected but not installed. Node/Rust micro-replays, Docker-in-Docker "
            "isolation, Git repository-fixture tests, delivery inspection, other platforms and "
            "production deployment are outside this receipt and must be evidenced separately."
        ),
    }
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "passed": passed}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
