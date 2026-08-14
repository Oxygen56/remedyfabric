from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts.presentation_readiness import ROOT, presentation_failures


class PresentationReadinessTests(unittest.TestCase):
    def test_module_imports_when_executed_as_a_script_dependency(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import runpy; "
                    "module = runpy.run_path('scripts/presentation_readiness.py'); "
                    "assert callable(module['presentation_failures'])"
                ),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_only_self_referential_post_head_gates_are_deferred(self) -> None:
        failures = [
            "reproducibility.public_ci: must be true",
            "judge_delivery.dashboard: must be true",
            "agentteams.complete_multi_agent_loop: must be true",
        ]
        with (
            patch("scripts.presentation_readiness.build_manifest", return_value={}),
            patch("scripts.presentation_readiness.evaluate", return_value=failures),
        ):
            self.assertEqual(
                presentation_failures(ROOT),
                ["agentteams.complete_multi_agent_loop: must be true"],
            )


if __name__ == "__main__":
    unittest.main()
