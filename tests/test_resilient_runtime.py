import unittest

from remedyfabric.faults import canonical_digest
from remedyfabric.resilient import run_resilient_matrix


class ResilientRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = run_resilient_matrix().payload
        cls.trials = {trial["trial_id"]: trial for trial in cls.matrix["trials"]}

    def test_one_faulty_worker_recovers_without_unsafe_release(self):
        expected_faults = {
            "crash",
            "equivocation",
            "forged",
            "replay",
            "unsafe_patch",
            "context_mismatch",
            "role_impersonation",
            "timeout",
        }
        single = [trial for trial in self.matrix["trials"] if trial["scope"] == "single-worker"]
        observed_faults = {
            next(iter(trial["fault_injection"]["worker_faults"].values())) for trial in single
        }
        self.assertEqual(observed_faults, expected_faults)
        for trial in single:
            with self.subTest(trial=trial["trial_id"]):
                self.assertTrue(trial["outcome"]["recovered"])
                self.assertTrue(trial["outcome"]["released"])
                self.assertFalse(trial["outcome"]["unsafe_release"])
                self.assertTrue(trial["final_verification"]["visible"]["passed"])
                self.assertTrue(trial["final_verification"]["invariant"]["passed"])
                counts = trial["quorum_decision"]["approval_counts"]
                self.assertGreaterEqual(counts["worker-proposals"], 2)
                self.assertEqual(counts["verifier"], 2)

        metrics = self.matrix["metrics"]
        self.assertEqual(metrics["single_worker_unsafe_releases"], 0)
        self.assertGreaterEqual(metrics["single_worker_relative_recovery_vs_baseline"], 0.90)

    def test_tested_out_of_boundary_cases_fail_closed_and_restore_bytes(self):
        beyond = [trial for trial in self.matrix["trials"] if trial["scope"] == "out-of-boundary"]
        self.assertEqual(len(beyond), 13)
        for trial in beyond:
            with self.subTest(trial=trial["trial_id"]):
                self.assertFalse(trial["outcome"]["released"])
                self.assertTrue(trial["outcome"]["fail_closed"])
                self.assertFalse(trial["outcome"]["unsafe_release"])
                self.assertTrue(trial["outcome"]["rollback_verified_byte_exact"])
                transaction = trial["filesystem_transaction"]
                self.assertFalse(transaction["workspace_write_attempted_before_authorization"])
                if transaction["workspace_materialization_attempted_after_authorization"]:
                    self.assertTrue(transaction["quorum_authorized"])
                    self.assertTrue(transaction["governor_quorum_approved"])
                self.assertEqual(
                    transaction["final_snapshot_digest"],
                    trial["run_context"]["snapshot_digest"],
                )

        collusion = self.trials["out-colluding-unsafe-workers"]
        transaction = collusion["filesystem_transaction"]
        self.assertTrue(transaction["candidate_staged_before_authorization"])
        self.assertFalse(transaction["candidate_applied_before_decision"])
        self.assertFalse(transaction["workspace_write_attempted_before_authorization"])
        self.assertNotEqual(
            transaction["staging_snapshot_digest"],
            collusion["run_context"]["snapshot_digest"],
        )
        self.assertEqual(
            transaction["patched_snapshot_digest"],
            collusion["run_context"]["snapshot_digest"],
        )
        self.assertIn("CONTROL_REJECTION", collusion["reason_codes"])

        for trial_id in (
            "out-colluding-traversal-workers",
            "out-colluding-symlink-workers",
        ):
            with self.subTest(trial=trial_id):
                negative = self.trials[trial_id]
                negative_transaction = negative["filesystem_transaction"]
                self.assertIsNotNone(negative_transaction["staging_apply_error"])
                self.assertFalse(negative_transaction["candidate_staged_before_authorization"])
                self.assertFalse(
                    negative_transaction["workspace_write_attempted_before_authorization"]
                )
                self.assertTrue(negative_transaction["outside_bytes_unchanged"])
                self.assertEqual(
                    negative_transaction["outside_digest_before"],
                    negative_transaction["outside_digest_after"],
                )
        self.assertEqual(self.matrix["metrics"]["tested_out_of_boundary_fail_closed_rate"], 1.0)

    def test_raw_decisions_bind_roles_context_and_evidence_hashes(self):
        required_roles = {
            "worker",
            "verifier",
            "challenger",
            "governor",
            "release-manager",
        }
        for trial in self.matrix["trials"]:
            with self.subTest(trial=trial["trial_id"]):
                roles = {member["role"] for member in trial["run_context"]["membership"]}
                self.assertEqual(roles, required_roles)
                self.assertEqual(len(trial["quorum_decision"]["receipt_digest"]), 64)
                self.assertEqual(len(trial["trial_evidence_digest"]), 64)
                self.assertGreaterEqual(len(trial["attestations_presented"]), 3)
                for attestation in trial["attestations_presented"]:
                    self.assertEqual(len(attestation["artifact_digest"]), 64)
                    self.assertEqual(len(attestation["fingerprint"]), 64)

        payload = dict(self.matrix)
        claimed = payload.pop("matrix_evidence_digest")
        self.assertEqual(claimed, canonical_digest(payload))

    def test_matrix_champion_gate_passes_every_preregistered_check(self):
        self.assertTrue(self.matrix["gate"]["passed"])
        self.assertTrue(all(self.matrix["gate"]["checks"].values()))
        self.assertEqual(self.matrix["metrics"]["trial_count"], 22)
        self.assertEqual(self.matrix["metrics"]["preauthorization_workspace_write_attempts"], 0)
        self.assertEqual(self.matrix["metrics"]["outside_write_violations"], 0)


if __name__ == "__main__":
    unittest.main()
