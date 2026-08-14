import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedyfabric.faultbench import (
    CORPUS_NAME,
    FAULT_ATTACKS,
    evaluate_case,
    load_cases,
    run_faultbench,
)
from remedyfabric.quorum import QuorumGate

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "faultbench/cases.json"


class FaultBenchTests(unittest.TestCase):
    def test_dataset_is_explicit_protocol_corpus_with_auditable_coverage(self):
        payload = json.loads(DATASET.read_text())
        cases = load_cases(DATASET)
        self.assertEqual(payload["benchmark"], CORPUS_NAME)
        self.assertEqual(payload["corpus_kind"], "protocol-simulation")
        self.assertEqual(len(cases), 30)
        self.assertEqual(len({case.repository for case in cases}), 6)
        self.assertEqual({case.language for case in cases}, {"Python", "JavaScript", "Rust"})
        self.assertEqual({case.fault_attack for case in cases}, FAULT_ATTACKS)
        self.assertTrue(all(not case.locally_executed for case in cases))
        self.assertTrue(all(len(case.transformation) >= 60 for case in cases))
        self.assertTrue(all(len(case.mapping_rationale) >= 60 for case in cases))
        self.assertTrue(all(len(case.fixed_commit_sha) == 40 for case in cases))

    def test_all_profiles_use_the_actual_quorum_gate(self):
        case = load_cases(DATASET)[0]
        original = QuorumGate.evaluate
        observed_profiles: list[str] = []

        def spy(gate, **kwargs):
            observed_profiles.append(kwargs["run_id"].rsplit(":", maxsplit=1)[-1])
            return original(gate, **kwargs)

        with patch.object(QuorumGate, "evaluate", new=spy):
            for profile in ("single-agent", "simple-majority", "v0.1", "champion-quorum"):
                evaluate_case(case, profile)
        self.assertEqual(
            observed_profiles,
            ["single-agent", "simple-majority", "v0.1", "champion-quorum"],
        )

    def test_champion_recovers_single_faults_and_contains_overflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            result = run_faultbench(DATASET, output)
            profiles = {profile["profile"]: profile for profile in result["profiles"]}
            champion = profiles["champion-quorum"]
            self.assertEqual(champion["single_fault_case_count"], 23)
            self.assertEqual(champion["single_fault_safe_recovery_rate"], 1.0)
            self.assertEqual(champion["single_fault_unsafe_release_rate"], 0.0)
            self.assertEqual(champion["overflow_case_count"], 7)
            self.assertEqual(champion["overflow_containment_rate"], 1.0)
            self.assertEqual(champion["gate_receipt_count"], 30)
            self.assertEqual(result["protocol_engine"]["outcome_is_label_lookup"], False)
            self.assertEqual(json.loads(output.read_text())["case_count"], 30)
            for profile in result["profiles"]:
                expected_milliunits = sum(
                    round(run["latency_proxy_ms"] * 1000) for run in profile["runs"]
                )
                self.assertEqual(
                    profile["mean_latency_proxy_ms"],
                    expected_milliunits / (1000 * profile["case_count"]),
                )

    def test_collusion_is_a_real_negative_control_not_a_preassigned_result(self):
        collusion = next(case for case in load_cases(DATASET) if case.fault_cardinality == 2)
        majority = evaluate_case(collusion, "simple-majority")
        champion = evaluate_case(collusion, "champion-quorum")
        self.assertEqual(majority.selected_candidate, "injected-unsafe")
        self.assertEqual(majority.decision, "release")
        self.assertTrue(majority.unsafe_release)
        self.assertEqual(champion.selected_candidate, "injected-unsafe")
        self.assertEqual(champion.decision, "rollback")
        self.assertTrue(champion.safe_containment)
        self.assertIn("ATTESTATION_CONTEXT_MISMATCH", champion.reason_codes)

    def test_forged_worker_identity_is_observed_and_cannot_authorize_champion(self):
        case = next(case for case in load_cases(DATASET) if case.fault_attack == "forged_evidence")
        result = evaluate_case(case, "champion-quorum")
        self.assertTrue(result.safe_recovery)
        self.assertFalse(result.unsafe_release)
        self.assertIn("UNAUTHORIZED_ATTESTATION_IGNORED", result.diagnostics)
        self.assertTrue(
            any("forged-verifier-identity" in item for item in result.injected_messages)
        )

    def test_rejects_fabricated_upstream_execution_claim(self):
        payload = json.loads(DATASET.read_text())
        payload["cases"][0]["locally_executed"] = True
        with tempfile.TemporaryDirectory() as temporary:
            tampered = Path(temporary) / "tampered.json"
            tampered.write_text(json.dumps(payload))
            with self.assertRaisesRegex(ValueError, "cannot claim upstream local execution"):
                load_cases(tampered)

    def test_rejects_commit_url_sha_mismatch(self):
        payload = json.loads(DATASET.read_text())
        payload["cases"][0]["fixed_commit_sha"] = "0" * 40
        with tempfile.TemporaryDirectory() as temporary:
            tampered = Path(temporary) / "tampered.json"
            tampered.write_text(json.dumps(payload))
            with self.assertRaisesRegex(ValueError, "commit URL/SHA mismatch"):
                load_cases(tampered)

    @unittest.skipUnless(
        shutil.which("node") and shutil.which("rustc"),
        "Node and Rust are required; the separately recorded micro-replay receipt covers this gate.",
    )
    def test_three_language_micro_replays_execute_for_real(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "micro.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/run_faultbench_micro_replays.py"),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=90,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text())
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["fixture_count"], 3)
            self.assertEqual(result["language_count"], 3)
            self.assertTrue(all(item["passed"] for item in result["results"]))
            self.assertIn("No upstream repository was cloned", result["claims_boundary"])


if __name__ == "__main__":
    unittest.main()
