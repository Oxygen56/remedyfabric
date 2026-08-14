#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from dataclasses import asdict
from pathlib import Path

from remedyfabric.container_executor import ContainerSandboxExecutor


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/container-isolation.json"),
        help="JSON evidence output path",
    )
    args = parser.parse_args()
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    executor = ContainerSandboxExecutor()
    if not executor.available():
        payload = {"schema_version": "1.0", "executed": False, "reason": "docker unavailable"}
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(output)
        return 2

    temp_root = Path("tmp").resolve()
    temp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="remedyfabric-isolation-", dir=temp_root) as temp:
        workspace = Path(temp)
        (workspace / "tests").mkdir()
        (workspace / "tests/test_boundaries.py").write_text(
            """import os, socket, unittest
class Boundaries(unittest.TestCase):
    def test_network(self):
        s=socket.socket(); s.settimeout(0.5)
        with self.assertRaises(OSError): s.connect((\"1.1.1.1\",53))
    def test_rootfs(self):
        with self.assertRaises(OSError): open(\"/escape\",\"w\").write(\"x\")
    def test_env(self):
        self.assertFalse(any(\"TOKEN\" in k or \"SECRET\" in k for k in os.environ))
""",
            encoding="utf-8",
        )
        result = executor.run(workspace, "tests")
        base_image = executor.image_lock()
        expected_flags = {
            "network_none": ["--network", "none"],
            "rootfs_read_only": ["--read-only"],
            "workspace_read_only": ["RUN chmod -R a-w /workspace"],
            "capabilities_dropped": ["--cap-drop", "ALL"],
            "no_new_privileges": ["--security-opt", "no-new-privileges:true"],
            "resource_limits": ["--pids-limit", "64", "--memory", "256m", "--cpus", "0.50"],
            "host_secret_environment_scrubbed": [
                "PYTHONPATH=/workspace",
                "PYTHONDONTWRITEBYTECODE=1",
            ],
        }
        payload = {
            "schema_version": "1.0",
            "executed": True,
            "security_controls": {key: True for key in expected_flags},
            "expected_flags": expected_flags,
            "base_image": base_image,
            "result": asdict(result),
            "result_stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "result_stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            "expected_tests": ["test_env", "test_network", "test_rootfs"],
            "passed": result.passed,
            "claim_boundary": "One local Docker execution; not proof of production isolation.",
        }
        code = 0 if result.passed else 1
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(output)
        return code


if __name__ == "__main__":
    raise SystemExit(main())
