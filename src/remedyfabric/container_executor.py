from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from .models import CommandResult


class ContainerSandboxExecutor:
    """Run verification in a least-privilege Docker container.

    The workspace is read-only, networking is disabled, the root filesystem is read-only,
    Linux capabilities are removed, privilege escalation is disabled and resource limits are
    explicit. This executor verifies candidates; it does not apply patches inside the container.
    """

    def __init__(
        self,
        image: str = "python:3.12-slim",
        timeout_seconds: int = 180,
        memory: str = "256m",
        cpus: str = "0.50",
        pids_limit: int = 64,
    ) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit

    @staticmethod
    def available() -> bool:
        if shutil.which("docker") is None:
            return False
        probe = subprocess.run(
            ("docker", "info", "--format", "{{.ServerVersion}}"),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        return probe.returncode == 0

    def _image_tag(self, workspace: Path) -> str:
        digest = hashlib.sha256()
        for path in sorted(workspace.rglob("*")):
            if path.is_file():
                digest.update(path.relative_to(workspace).as_posix().encode())
                digest.update(path.read_bytes())
        return f"remedyfabric-verifier:{digest.hexdigest()[:16]}"

    def _build_image(self, workspace: Path, tag: str) -> subprocess.CompletedProcess[str]:
        if not re.fullmatch(r"[A-Za-z0-9./:_-]+", self.image):
            raise ValueError("container image contains unsupported characters")
        dockerfile = (
            f"FROM {self.image}\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            "RUN chmod -R a-w /workspace\n"
        )
        try:
            return subprocess.run(
                (
                    "docker",
                    "build",
                    "--quiet",
                    "--network",
                    "none",
                    "--label",
                    "remedyfabric.ephemeral=true",
                    "--tag",
                    tag,
                    "--file",
                    "-",
                    str(workspace.resolve()),
                ),
                input=dockerfile,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                exc.cmd,
                124,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or "",
                stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or "",
            )

    def command(self, image: str, test_directory: str) -> tuple[str, ...]:
        if Path(test_directory).is_absolute() or ".." in Path(test_directory).parts:
            raise ValueError("test directory must stay inside the workspace")
        return (
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
            str(self.pids_limit),
            "--memory",
            self.memory,
            "--cpus",
            self.cpus,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--workdir",
            "/workspace",
            "--env",
            "PYTHONPATH=/workspace",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            image,
            "python",
            "-m",
            "unittest",
            "discover",
            "-s",
            test_directory,
            "-v",
        )

    def run(self, workspace: Path, test_directory: str) -> CommandResult:
        tag = self._image_tag(workspace)
        build = self._build_image(workspace, tag)
        if build.returncode != 0:
            return CommandResult(
                command=("docker", "build", tag),
                returncode=build.returncode,
                stdout=build.stdout[-12_000:],
                stderr=build.stderr[-12_000:],
                duration_ms=0,
            )
        command = self.command(tag, test_directory)
        start = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            result = CommandResult(
                command=command,
                returncode=completed.returncode,
                stdout=completed.stdout[-12_000:],
                stderr=completed.stderr[-12_000:],
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                command=command,
                returncode=124,
                stdout=(exc.stdout or "")[-12_000:] if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "")[-12_000:] if isinstance(exc.stderr, str) else "",
                duration_ms=(time.perf_counter() - start) * 1000,
                timed_out=True,
            )
        finally:
            subprocess.run(
                ("docker", "image", "rm", "--force", tag),
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
        return result

    def image_lock(self) -> dict[str, object]:
        """Resolve the mutable input reference to the local registry digest and image ID."""

        inspected = subprocess.run(
            ("docker", "image", "inspect", self.image, "--format", "{{json .RepoDigests}}|{{.Id}}"),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if inspected.returncode != 0:
            raise RuntimeError("container base image is not locally inspectable")
        repo_json, image_id = inspected.stdout.strip().split("|", 1)
        repo_digests = json.loads(repo_json)
        return {
            "reference": self.image,
            "repo_digests": repo_digests,
            "image_id": image_id,
        }
