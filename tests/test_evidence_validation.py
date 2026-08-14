from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from remedyfabric.evidence_validation import (
    canonical_digest,
    validate_core_evidence,
    validate_faultbench,
    validate_resilient_matrix,
)
from remedyfabric.resilient import run_resilient_matrix

ROOT = Path(__file__).resolve().parents[1]


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class EvidenceValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resilient = run_resilient_matrix().payload

    @staticmethod
    def rehash(payload: dict, trial_index: int = 0) -> None:
        trial = payload["trials"][trial_index]
        trial.pop("trial_evidence_digest", None)
        trial["trial_evidence_digest"] = canonical_digest(trial)
        payload.pop("matrix_evidence_digest", None)
        payload["matrix_evidence_digest"] = canonical_digest(payload)

    def test_current_core_receipts_recompute_cleanly(self) -> None:
        self.assertEqual(
            validate_core_evidence(
                root=ROOT,
                resilient=self.resilient,
                model=load("artifacts/quorum-model.json"),
                faultbench=load("artifacts/faultbench-results.json"),
                sources=load("artifacts/faultbench-source-verification.json"),
                micro=load("artifacts/faultbench-micro-replays.json"),
                isolation=load("artifacts/container-isolation.json"),
            ),
            [],
        )

    def test_tampered_trial_cannot_hide_behind_passed_flag(self) -> None:
        payload = deepcopy(self.resilient)
        payload["trials"][0]["outcome"]["recovered"] = False
        failures = validate_resilient_matrix(payload)
        self.assertTrue(any("digest" in failure for failure in failures))
        self.assertTrue(any("outcome.semantic_replay" in failure for failure in failures))

    def test_rehashed_preauthorization_write_still_fails_semantic_gate(self) -> None:
        payload = deepcopy(self.resilient)
        trial = payload["trials"][0]
        transaction = trial["filesystem_transaction"]
        transaction["workspace_write_attempted_before_authorization"] = True
        payload["metrics"]["preauthorization_workspace_write_attempts"] = 1
        self.rehash(payload)

        failures = validate_resilient_matrix(payload)

        self.assertTrue(any("preauthorization" in failure for failure in failures))

    def test_rehashed_rollback_story_cannot_replace_preregistered_release(self) -> None:
        payload = deepcopy(self.resilient)
        trial = payload["trials"][0]
        for actor_id in ("verifier-1", "verifier-2", "challenger-1", "governor-1"):
            trial["control_executions"][actor_id]["verdict"] = "reject"
        for attestation in trial["attestations_presented"]:
            attestation["verdict"] = "reject"
            attestation["fingerprint"] = canonical_digest(
                {
                    "actor_id": attestation["actor_id"],
                    "role": attestation["role"],
                    "verdict": "reject",
                    "binding_digest": attestation["claimed_binding_digest"],
                    "detail": attestation["detail"],
                }
            )
        decision = trial["quorum_decision"]
        decision.update(
            {
                "authorized": False,
                "action": "rollback",
                "approval_counts": {
                    "worker-proposals": 3,
                    "verifier": 0,
                    "challenger": 0,
                    "governor": 0,
                },
                "reason_codes": [
                    "CHALLENGER_QUORUM_MISSING",
                    "CONTROL_REJECTION",
                    "GOVERNOR_QUORUM_MISSING",
                    "VERIFIER_QUORUM_MISSING",
                ],
            }
        )
        decision["receipt_digest"] = canonical_digest(
            {
                "run_id": trial["run_context"]["run_id"],
                "snapshot_digest": trial["run_context"]["snapshot_digest"],
                "candidate_digest": decision["candidate_digest"],
                "requested_by": trial["release_requester"]["actor_id"],
                "authorized": False,
                "action": "rollback",
                "approval_counts": decision["approval_counts"],
                "reason_codes": decision["reason_codes"],
                "diagnostics": decision["diagnostics"],
            }
        )
        self.rehash(payload)

        failures = validate_resilient_matrix(payload)

        self.assertTrue(any("controls.verifier.verdict" in failure for failure in failures))

    def test_rehashed_raw_proposal_tamper_still_fails(self) -> None:
        payload = deepcopy(self.resilient)
        emission = payload["trials"][0]["workers"][0]["emissions"][0]
        emission["actor_id"] = "worker-2"
        self.rehash(payload)

        failures = validate_resilient_matrix(payload)

        self.assertTrue(any("worker.emission_semantics" in failure for failure in failures))

    def test_rehashed_raw_candidate_tamper_still_fails(self) -> None:
        payload = deepcopy(self.resilient)
        emission = payload["trials"][0]["workers"][0]["emissions"][0]
        candidate = emission["candidate"]
        candidate["edits"][0]["new"] += "\n# forged alternate patch\n"
        emission["candidate_payload_digest"] = canonical_digest(candidate)
        proposal_digest = canonical_digest(
            {
                "skill_name": candidate["skill_name"],
                "skill_version": candidate["skill_version"],
                "provider_name": candidate["provider_name"],
                "provider_version": candidate["provider_version"],
                "edits": [
                    {"path": edit["path"], "old": edit["old"], "new": edit["new"]}
                    for edit in candidate["edits"]
                ],
            }
        )
        emission["actual_patch_digest"] = proposal_digest
        emission["claimed_patch_digest"] = proposal_digest
        self.rehash(payload)

        failures = validate_resilient_matrix(payload)

        self.assertTrue(any("worker.emission_semantics" in failure for failure in failures))

    def test_rehashed_control_artifact_digest_tamper_still_fails(self) -> None:
        payload = deepcopy(self.resilient)
        payload["trials"][0]["control_executions"]["verifier-1"]["artifact_digest"] = "f" * 64
        self.rehash(payload)

        failures = validate_resilient_matrix(payload)

        self.assertTrue(any("controls.verifier.artifact_digest" in failure for failure in failures))

    def test_faultbench_cannot_replace_gate_receipt_with_self_reported_release(self) -> None:
        payload = load("artifacts/faultbench-results.json")
        run = payload["profiles"][-1]["runs"][0]
        run["decision"] = "release"
        run["selected_candidate"] = "trusted-fix"
        run["safe_recovery"] = True
        run["safe_containment"] = False
        run["unsafe_release"] = False
        run["rollback"] = False
        run["proposal_count"] = 0
        run["attestation_count"] = 0
        run["gate_receipt_digest"] = "0" * 64

        failures = validate_faultbench(payload, ROOT / "faultbench/cases.json")

        self.assertIn("faultbench.semantic_replay", failures)


if __name__ == "__main__":
    unittest.main()
