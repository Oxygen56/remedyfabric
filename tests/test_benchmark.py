import json
import tempfile
import unittest
from pathlib import Path

from remedyfabric.benchmark import run_benchmark
from remedyfabric.report import render_dashboard


class BenchmarkTests(unittest.TestCase):
    def test_full_profile_and_ablations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = run_benchmark(root / "benchmark.json")
            profiles = {item["profile"]: item for item in result["profiles"]}
            full = profiles["full"]
            self.assertEqual(full["task_success_rate"], 1.0)
            self.assertEqual(full["recovery_success_rate"], 1.0)
            self.assertEqual(full["safety_violation_rate"], 0.0)
            self.assertEqual(full["ledger_integrity_rate"], 1.0)
            self.assertLess(
                profiles["single-agent"]["task_success_rate"], full["task_success_rate"]
            )
            self.assertLess(profiles["no-verifier"]["task_success_rate"], full["task_success_rate"])
            self.assertGreater(profiles["no-governor"]["safety_violation_rate"], 0.0)
            dashboard = root / "dashboard.html"
            render_dashboard(root / "benchmark.json", dashboard)
            self.assertIn("RemedyFabric", dashboard.read_text(encoding="utf-8"))
            self.assertEqual(json.loads((root / "benchmark.json").read_text())["scenario_count"], 8)


if __name__ == "__main__":
    unittest.main()
