from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from .models import CommandResult


class SandboxExecutor:
    """Runs only an explicit Python unittest command in a bounded local workspace."""

    def __init__(self, timeout_seconds: int = 20) -> None:
        self.timeout_seconds = timeout_seconds

    def run(self, workspace: Path, command: tuple[str, ...]) -> CommandResult:
        if len(command) < 3 or command[1:3] != ("-m", "unittest"):
            raise ValueError("only `python -m unittest` commands are permitted")
        start = time.perf_counter()
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(workspace),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
        }
        try:
            completed = subprocess.run(
                command,
                cwd=workspace,
                env=safe_env,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            return CommandResult(
                command=command,
                returncode=completed.returncode,
                stdout=completed.stdout[-12_000:],
                stderr=completed.stderr[-12_000:],
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command=command,
                returncode=124,
                stdout=(exc.stdout or "")[-12_000:] if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "")[-12_000:] if isinstance(exc.stderr, str) else "",
                duration_ms=(time.perf_counter() - start) * 1000,
                timed_out=True,
            )
