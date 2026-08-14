import importlib.util
import unittest
from pathlib import Path

from remedyfabric.faultbench import load_cases

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_faultbench_sources", ROOT / "scripts/verify_faultbench_sources.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FaultBenchSourceValidationTests(unittest.TestCase):
    def test_official_payload_comparison_is_fail_closed(self):
        case = load_cases(ROOT / "faultbench/cases.json")[0]
        pull = {
            "html_url": case.pr_url,
            "number": case.pr_number,
            "state": "closed",
            "merged": True,
            "title": case.title,
            "merged_at": case.merged_at,
            "merge_commit_sha": case.fixed_commit_sha,
        }
        commit = {"sha": case.fixed_commit_sha, "html_url": case.commit_url}
        license_payload = {"license": {"spdx_id": case.license}}
        issue = {"html_url": case.issue_url}
        valid = MODULE.validate_api_payloads(case, pull, commit, license_payload, issue)
        self.assertTrue(valid["passed"])
        pull["merge_commit_sha"] = "0" * 40
        invalid = MODULE.validate_api_payloads(case, pull, commit, license_payload, issue)
        self.assertFalse(invalid["passed"])
        self.assertTrue(
            any(
                check["field"] == "pull.merge_commit_sha" and not check["passed"]
                for check in invalid["checks"]
            )
        )


if __name__ == "__main__":
    unittest.main()
