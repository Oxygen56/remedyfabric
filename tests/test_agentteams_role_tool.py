from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from remedyfabric.faults import canonical_digest
from remedyfabric.snapshot import WorkspaceSnapshot
from scripts.agentteams_role_tool import EXPECTED_NEW, EXPECTED_OLD, execute

VISIBLE_TEST = (
    "import unittest\n"
    "from app.service import mean\n\n"
    "class VisibleContractTests(unittest.TestCase):\n"
    "    def test_empty_input_contract(self):\n"
    "        self.assertEqual(mean([]), 0.0)\n"
)
INVARIANT_TEST = (
    "import unittest\n"
    "from app.service import mean\n\n"
    "class NonEmptyInvariantTests(unittest.TestCase):\n"
    "    def test_non_empty_mean_is_preserved(self):\n"
    "        self.assertEqual(mean([2, 4]), 3.0)\n"
)


class AgentTeamsRoleToolTests(unittest.TestCase):
    def base(self, actor: str, snapshot_digest: str) -> dict:
        return {
            "actor_id": actor,
            "run_id": "run-test",
            "snapshot_digest": snapshot_digest,
        }

    def receipt_inputs(self, count: int = 2) -> list[str]:
        return [f"{index:x}" * 64 for index in range(2, 2 + count)]

    def prepare_faulty_workspace(
        self,
        directory: str,
        *,
        include_visible: bool = True,
        include_invariant: bool = True,
        already_repaired: bool = False,
    ) -> str:
        root = Path(directory)
        (root / "app").mkdir(exist_ok=True)
        (root / "app/__init__.py").write_text("", encoding="utf-8")
        (root / "app/service.py").write_text(
            EXPECTED_NEW if already_repaired else EXPECTED_OLD,
            encoding="utf-8",
        )
        (root / "tests").mkdir(exist_ok=True)
        (root / "invariants").mkdir(exist_ok=True)
        if include_visible:
            (root / "tests/test_visible_contract.py").write_text(
                VISIBLE_TEST,
                encoding="utf-8",
            )
        if include_invariant:
            (root / "invariants/test_non_empty_invariant.py").write_text(
                INVARIANT_TEST,
                encoding="utf-8",
            )
        return WorkspaceSnapshot.capture(root).digest

    def propose(self, actor: str) -> tuple[dict, str]:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = self.prepare_faulty_workspace(temporary)
            self.assertEqual(Path(temporary, "app/service.py").read_text(), EXPECTED_OLD)
            result = execute(
                "proposer",
                {
                    **self.base(actor, snapshot),
                    "workspace": temporary,
                },
            )
            self.assertEqual(result["observed_snapshot_digest"], snapshot)
            self.assertEqual(WorkspaceSnapshot.capture(Path(temporary)).digest, snapshot)
            return result, snapshot

    def execute_workspace_role(
        self,
        role: str,
        actor: str,
        candidate: dict | None = None,
    ) -> tuple[dict, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = self.prepare_faulty_workspace(temporary)
            with tempfile.TemporaryDirectory() as staged_directory:
                expected_staged_snapshot = self.prepare_faulty_workspace(
                    staged_directory, already_repaired=True
                )
            self.assertEqual((root / "app/service.py").read_text(), EXPECTED_OLD)
            payload = {
                **self.base(actor, snapshot),
                "workspace": temporary,
                "input_receipt_digests": self.receipt_inputs(),
            }
            if candidate is not None:
                payload["candidate"] = candidate
            result = execute(role, payload)
            self.assertEqual((root / "app/service.py").read_text(), EXPECTED_NEW)
            binding = result["artifact"]["workspace_binding"]
            self.assertEqual(binding["derived_prechange_snapshot_digest"], snapshot)
            self.assertEqual(binding["staged_snapshot_digest"], expected_staged_snapshot)
            self.assertEqual(binding["candidate_digest"], result["attestation"]["candidate_digest"])
            return result, snapshot, expected_staged_snapshot

    def assert_successful_suites(self, artifact: dict) -> None:
        self.assertEqual(artifact["returncodes"], [0, 0])
        self.assertEqual(len(artifact["test_counts"]), 2)
        for count, cases in zip(artifact["test_counts"], artifact["test_cases"], strict=True):
            self.assertGreater(count, 0)
            self.assertEqual(len(cases), count)
            self.assertTrue(all(case["status"] == "ok" for case in cases))

    def test_two_proposers_emit_the_same_candidate_bound_to_formal_snapshots(self) -> None:
        first, first_snapshot = self.propose("rf-proposer-a")
        second, second_snapshot = self.propose("rf-proposer-b")

        self.assertEqual(first_snapshot, second_snapshot)
        self.assertEqual(first["candidate_digest"], second["candidate_digest"])
        self.assertEqual(first["patch_candidate"]["edits"][0]["new"], EXPECTED_NEW)
        self.assertEqual(first["proposal"]["snapshot_digest"], first_snapshot)
        self.assertEqual(second["proposal"]["snapshot_digest"], second_snapshot)

    def test_cloud_preflight_stops_before_request_without_credentials(self) -> None:
        payload = self.base("rf-verifier", "1" * 64)
        payload["input_receipt_digests"] = self.receipt_inputs()
        result = execute("alibaba-cloud-preflight", payload)
        self.assertEqual(result["status"], "blocked_before_cloud_api")
        self.assertFalse(result["request_sent"])

    def test_governor_applies_candidate_and_binds_pre_and_staged_snapshots(self) -> None:
        result, snapshot, staged_snapshot = self.execute_workspace_role("governor", "rf-governor")

        self.assertEqual(result["attestation"]["verdict"], "approve")
        self.assertEqual(result["attestation"]["snapshot_digest"], snapshot)
        self.assertNotEqual(staged_snapshot, snapshot)
        self.assertEqual(result["artifact"]["risk_score"], 0)

    def test_verifier_applies_candidate_and_executes_nonempty_distinct_suites(self) -> None:
        result, snapshot, staged_snapshot = self.execute_workspace_role("verifier", "rf-verifier")

        self.assert_successful_suites(result["artifact"])
        self.assertEqual(result["attestation"]["role"], "verifier")
        self.assertEqual(result["attestation"]["evidence_kind"], "test")
        self.assertEqual(result["attestation"]["verdict"], "approve")
        self.assertEqual(result["attestation"]["snapshot_digest"], snapshot)
        self.assertNotEqual(staged_snapshot, snapshot)
        self.assertEqual(result["consumed_receipt_digests"], self.receipt_inputs())
        visible_ids = {case["test_id"] for case in result["artifact"]["test_cases"][0]}
        invariant_ids = {case["test_id"] for case in result["artifact"]["test_cases"][1]}
        self.assertTrue(visible_ids.isdisjoint(invariant_ids))

    def test_challenger_rejects_real_negative_mutant_with_invariant(self) -> None:
        result, snapshot, staged_snapshot = self.execute_workspace_role(
            "challenger", "rf-challenger"
        )

        artifact = result["artifact"]
        self.assert_successful_suites(artifact)
        self.assertTrue(artifact["test_and_invariant_suites_distinct"])
        negative = artifact["negative_control"]
        self.assertTrue(negative["rejected"])
        self.assertNotEqual(negative["returncode"], 0)
        self.assertGreater(negative["test_count"], 0)
        self.assertEqual(len(negative["test_cases"]), negative["test_count"])
        self.assertTrue(any(case["status"] != "ok" for case in negative["test_cases"]))
        self.assertEqual(result["attestation"]["role"], "challenger")
        self.assertEqual(result["attestation"]["evidence_kind"], "challenge")
        self.assertEqual(result["attestation"]["verdict"], "approve")
        self.assertEqual(result["attestation"]["snapshot_digest"], snapshot)
        self.assertNotEqual(staged_snapshot, snapshot)

    def test_reviewer_binds_two_converged_proposals_to_formal_snapshot(self) -> None:
        proposed, snapshot = self.propose("rf-proposer-a")
        candidate = proposed["patch_candidate"]
        first = proposed["proposal"]
        second = dict(first)
        second["actor_id"] = "rf-proposer-b"
        payload = self.base("rf-lead", snapshot)
        payload.update(
            {
                "candidate": candidate,
                "proposals": [first, second],
                "input_receipt_digests": ["a" * 64, "b" * 64],
            }
        )
        result = execute("reviewer", payload)

        self.assertTrue(result["artifact"]["converged"])
        self.assertEqual(result["artifact"]["candidate_digest"], proposed["candidate_digest"])
        self.assertIn("not a quorum attestation", result["artifact"]["authority_boundary"])

    def test_release_manager_replays_full_quorum_gate_from_typed_inputs(self) -> None:
        first, snapshot = self.propose("rf-proposer-a")
        second, second_snapshot = self.propose("rf-proposer-b")
        self.assertEqual(snapshot, second_snapshot)

        candidate = first["patch_candidate"]
        proposals = [first["proposal"], second["proposal"]]
        proposal_receipts = [
            canonical_digest(
                {
                    "kind": "proposal",
                    "actor_id": output["proposal"]["actor_id"],
                    "candidate_digest": output["candidate_digest"],
                    "proposal": output["proposal"],
                }
            )
            for output in (first, second)
        ]
        control_outputs = {}
        for actor, operation in (
            ("rf-verifier", "verifier"),
            ("rf-verifier-b", "verifier"),
            ("rf-lead", "reviewer"),
            ("rf-challenger", "challenger"),
            ("rf-governor", "governor"),
        ):
            if operation == "reviewer":
                payload = self.base(actor, snapshot)
                payload.update(
                    {
                        "candidate": candidate,
                        "proposals": proposals,
                        "input_receipt_digests": proposal_receipts,
                    }
                )
                control_outputs[actor] = execute(operation, payload)
            else:
                output, role_snapshot, _ = self.execute_workspace_role(operation, actor, candidate)
                self.assertEqual(role_snapshot, snapshot)
                control_outputs[actor] = output

        control_receipts = [
            canonical_digest({"kind": "control-helper", "actor_id": actor, "output": output})
            for actor, output in control_outputs.items()
        ]
        release_inputs = [*proposal_receipts, *control_receipts]
        payload = self.base("rf-release-manager", snapshot)
        payload.update(
            {
                "candidate": candidate,
                "proposals": proposals,
                "attestations": [
                    control_outputs[actor]["attestation"]
                    for actor in (
                        "rf-verifier",
                        "rf-verifier-b",
                        "rf-challenger",
                        "rf-governor",
                    )
                ],
                "input_receipt_digests": release_inputs,
            }
        )
        result = execute("release-manager", payload)

        self.assertTrue(all(proposal["snapshot_digest"] == snapshot for proposal in proposals))
        self.assertTrue(
            all(
                attestation["snapshot_digest"] == snapshot
                for attestation in payload["attestations"]
            )
        )
        self.assertTrue(result["decision"]["authorized"])
        self.assertEqual(result["decision"]["action"], "release")
        self.assertEqual(
            result["decision"]["approval_counts"],
            {"worker-proposals": 2, "verifier": 2, "challenger": 1, "governor": 1},
        )
        self.assertEqual(
            result["decision"]["receipt_digest"],
            canonical_digest(
                {
                    "run_id": "run-test",
                    "snapshot_digest": snapshot,
                    "candidate_digest": first["candidate_digest"],
                    "requested_by": "rf-release-manager",
                    "authorized": True,
                    "action": "release",
                    "approval_counts": result["decision"]["approval_counts"],
                    "reason_codes": [],
                    "diagnostics": [],
                }
            ),
        )
        self.assertEqual(result["consumed_receipt_digests"], sorted(release_inputs))

    def test_empty_visible_suite_is_rejected_before_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = self.prepare_faulty_workspace(temporary, include_visible=False)
            payload = {
                **self.base("rf-verifier", snapshot),
                "workspace": temporary,
                "input_receipt_digests": self.receipt_inputs(),
            }
            with self.assertRaisesRegex(ValueError, "lacks both visible and invariant tests"):
                execute("verifier", payload)

    def test_self_reported_snapshot_not_matching_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            actual_snapshot = self.prepare_faulty_workspace(temporary)
            self.assertNotEqual(actual_snapshot, "1" * 64)
            payload = {
                **self.base("rf-verifier", "1" * 64),
                "workspace": temporary,
                "input_receipt_digests": self.receipt_inputs(),
            }
            with self.assertRaisesRegex(
                ValueError, "faulty workspace does not match the bound snapshot"
            ):
                execute("verifier", payload)

    def test_already_repaired_workspace_is_rejected_as_stale_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = self.prepare_faulty_workspace(temporary, already_repaired=True)
            payload = {
                **self.base("rf-governor", snapshot),
                "workspace": temporary,
                "input_receipt_digests": self.receipt_inputs(),
            }
            with self.assertRaisesRegex(RuntimeError, "stale edit precondition"):
                execute("governor", payload)


if __name__ == "__main__":
    unittest.main()
