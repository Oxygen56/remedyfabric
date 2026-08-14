from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedyfabric.container_executor import ContainerSandboxExecutor

ROOT = Path(__file__).resolve().parents[1]


class ContainerExecutorTests(unittest.TestCase):
    def test_isolation_runner_honors_explicit_output_without_docker(self) -> None:
        script = ROOT / "scripts/run_container_isolation.py"
        spec = importlib.util.spec_from_file_location("run_container_isolation_test", script)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "replay" / "isolation.json"
            with (
                patch.object(module.ContainerSandboxExecutor, "available", return_value=False),
                patch.object(sys, "argv", [str(script), "--output", str(output)]),
            ):
                self.assertEqual(module.main(), 2)
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(payload["executed"])
        self.assertEqual(payload["reason"], "docker unavailable")

    def test_command_contains_all_security_boundaries(self) -> None:
        executor = ContainerSandboxExecutor()
        command = executor.command("remedyfabric-verifier:test", "tests")
        rendered = " ".join(command)
        for required in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "no-new-privileges:true",
            "--pids-limit 64",
            "--memory 256m",
            "--cpus 0.50",
            "remedyfabric-verifier:test",
        ):
            self.assertIn(required, rendered)

    def test_path_escape_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ContainerSandboxExecutor().command("remedyfabric-verifier:test", "../tests")

    @unittest.skipUnless(ContainerSandboxExecutor.available(), "Docker daemon unavailable")
    def test_live_container_has_no_network_or_rootfs_write(self) -> None:
        temp_root = ROOT / "tmp"
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="remedyfabric-container-", dir=temp_root) as temp:
            workspace = Path(temp)
            tests = workspace / "tests"
            tests.mkdir()
            (tests / "test_isolation.py").write_text(
                """import os
import socket
import unittest

class Isolation(unittest.TestCase):
    def test_network_is_blocked(self):
        sock = socket.socket()
        sock.settimeout(0.5)
        with self.assertRaises(OSError):
            sock.connect((\"1.1.1.1\", 53))

    def test_root_filesystem_is_read_only(self):
        with self.assertRaises(OSError):
            open(\"/escape.txt\", \"w\").write(\"escape\")

    def test_host_secrets_are_not_injected(self):
        forbidden = [key for key in os.environ if \"TOKEN\" in key or \"SECRET\" in key]
        self.assertEqual(forbidden, [])
""",
                encoding="utf-8",
            )
            result = ContainerSandboxExecutor().run(workspace, "tests")
            self.assertTrue(result.passed, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
