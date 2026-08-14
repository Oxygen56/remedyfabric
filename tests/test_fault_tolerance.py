import tempfile
import unittest
from pathlib import Path

from remedyfabric.faults import (
    AgentIdentity,
    AgentRole,
    Attestation,
    EvidenceBinding,
    EvidenceKind,
    FaultMode,
    Verdict,
    canonical_digest,
    inject_attestation_fault,
)
from remedyfabric.models import FileEdit, PatchCandidate
from remedyfabric.quorum import (
    CandidateProposal,
    QuorumConfig,
    QuorumGate,
    RecoveryAction,
    patch_digest,
)


class FaultToleranceTests(unittest.TestCase):
    def setUp(self):
        self.run_id = "run-001"
        self.snapshot = canonical_digest({"snapshot": "before"})
        self.candidate = PatchCandidate(
            "test-repair",
            "off-by-one",
            (FileEdit("src/example.py", "old", "new", "fix boundary"),),
            0.9,
        )
        self.other_candidate = PatchCandidate(
            "test-repair",
            "malicious",
            (FileEdit("src/example.py", "old", "unsafe", "unsafe change"),),
            0.1,
        )
        self.workers = (
            AgentIdentity("worker-1", AgentRole.WORKER),
            AgentIdentity("worker-2", AgentRole.WORKER),
        )
        self.verifiers = (
            AgentIdentity("verifier-1", AgentRole.VERIFIER),
            AgentIdentity("verifier-2", AgentRole.VERIFIER),
        )
        self.challenger = AgentIdentity("challenger-1", AgentRole.CHALLENGER)
        self.governor = AgentIdentity("governor-1", AgentRole.GOVERNOR)
        self.release_manager = AgentIdentity("release-1", AgentRole.RELEASE_MANAGER)
        self.members = (
            *self.workers,
            *self.verifiers,
            self.challenger,
            self.governor,
            self.release_manager,
        )
        self.gate = QuorumGate(self.members)

    def proposal(self, worker, candidate=None):
        return CandidateProposal.issue(
            worker, self.run_id, self.snapshot, candidate or self.candidate
        )

    def attestation(self, identity, verdict=Verdict.APPROVE, candidate=None):
        kinds = {
            AgentRole.VERIFIER: EvidenceKind.TEST,
            AgentRole.CHALLENGER: EvidenceKind.CHALLENGE,
            AgentRole.GOVERNOR: EvidenceKind.POLICY,
        }
        binding = EvidenceBinding(
            self.run_id,
            patch_digest(candidate or self.candidate),
            self.snapshot,
            kinds[identity.role],
            canonical_digest({"actor": identity.actor_id, "result": verdict.value}),
        )
        return Attestation.issue(identity, verdict, binding)

    def evaluate(self, proposals=None, attestations=None, requested_by=None):
        return self.gate.evaluate(
            run_id=self.run_id,
            snapshot_digest=self.snapshot,
            candidate=self.candidate,
            proposals=proposals
            if proposals is not None
            else [self.proposal(worker) for worker in self.workers],
            attestations=attestations
            if attestations is not None
            else [
                *(self.attestation(verifier) for verifier in self.verifiers),
                self.attestation(self.challenger),
                self.attestation(self.governor),
            ],
            requested_by=requested_by or self.release_manager,
        )

    def test_happy_path_requires_every_independent_gate(self):
        decision = self.evaluate()
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.action, RecoveryAction.RELEASE)
        self.assertEqual(dict(decision.approval_counts)["worker-proposals"], 2)
        self.assertEqual(len(decision.receipt_digest), 64)

    def test_single_worker_cannot_authorize_release(self):
        decision = self.evaluate(proposals=[self.proposal(self.workers[0])])
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.action, RecoveryAction.ROLLBACK)
        self.assertIn("PROPOSAL_QUORUM_MISSING", decision.reason_codes)

    def test_duplicate_worker_proposals_do_not_inflate_quorum(self):
        proposal = self.proposal(self.workers[0])
        decision = self.evaluate(proposals=[proposal, proposal, proposal])
        self.assertFalse(decision.authorized)
        self.assertEqual(dict(decision.approval_counts)["worker-proposals"], 1)

    def test_worker_equivocation_forces_rollback(self):
        decision = self.evaluate(
            proposals=[
                self.proposal(self.workers[0]),
                self.proposal(self.workers[0], self.other_candidate),
                self.proposal(self.workers[1]),
            ]
        )
        self.assertFalse(decision.authorized)
        self.assertIn("WORKER_EQUIVOCATION", decision.reason_codes)

    def test_control_rejection_cannot_be_outvoted(self):
        attestations = [
            *(self.attestation(verifier) for verifier in self.verifiers),
            self.attestation(self.challenger, Verdict.REJECT),
            self.attestation(self.governor),
        ]
        decision = self.evaluate(attestations=attestations)
        self.assertFalse(decision.authorized)
        self.assertIn("CONTROL_REJECTION", decision.reason_codes)

    def test_missing_or_equivocating_control_forces_rollback(self):
        without_challenger = [
            *(self.attestation(verifier) for verifier in self.verifiers),
            self.attestation(self.governor),
        ]
        missing_decision = self.evaluate(attestations=without_challenger)
        self.assertFalse(missing_decision.authorized)
        self.assertIn("CHALLENGER_QUORUM_MISSING", missing_decision.reason_codes)

        verifier = self.attestation(self.verifiers[0])
        equivocation = inject_attestation_fault(
            verifier,
            FaultMode.EQUIVOCATE,
            alternate_candidate_digest=patch_digest(self.other_candidate),
        )
        rest = [
            self.attestation(self.verifiers[1]),
            self.attestation(self.challenger),
            self.attestation(self.governor),
        ]
        equivocation_decision = self.evaluate(attestations=[*equivocation, *rest])
        self.assertFalse(equivocation_decision.authorized)
        self.assertIn("CONTROL_EQUIVOCATION", equivocation_decision.reason_codes)

    def test_forged_and_replayed_evidence_force_rollback(self):
        honest = self.attestation(self.verifiers[0])
        rest = [
            self.attestation(self.verifiers[1]),
            self.attestation(self.challenger),
            self.attestation(self.governor),
        ]
        forged = inject_attestation_fault(honest, FaultMode.FORGE_EVIDENCE)
        forged_decision = self.evaluate(attestations=[*forged, *rest])
        self.assertFalse(forged_decision.authorized)
        self.assertIn("INVALID_ATTESTATION_INTEGRITY", forged_decision.reason_codes)

        replayed = inject_attestation_fault(honest, FaultMode.REPLAY_EVIDENCE)
        replay_decision = self.evaluate(attestations=[*replayed, *rest])
        self.assertFalse(replay_decision.authorized)
        self.assertIn("ATTESTATION_CONTEXT_MISMATCH", replay_decision.reason_codes)

    def test_evidence_for_another_patch_cannot_authorize(self):
        attestations = [
            self.attestation(self.verifiers[0], candidate=self.other_candidate),
            self.attestation(self.verifiers[1]),
            self.attestation(self.challenger),
            self.attestation(self.governor),
        ]
        decision = self.evaluate(attestations=attestations)
        self.assertFalse(decision.authorized)
        self.assertIn("ATTESTATION_CONTEXT_MISMATCH", decision.reason_codes)

    def test_worker_cannot_act_as_release_manager_or_control_vote(self):
        decision = self.evaluate(requested_by=self.workers[0])
        self.assertFalse(decision.authorized)
        self.assertIn("REQUESTER_NOT_RELEASE_MANAGER", decision.reason_codes)

        forged_identity = AgentIdentity(self.workers[0].actor_id, AgentRole.VERIFIER)
        forged_binding = EvidenceBinding(
            self.run_id,
            patch_digest(self.candidate),
            self.snapshot,
            EvidenceKind.TEST,
            canonical_digest({"forged": True}),
        )
        forged_vote = Attestation.issue(forged_identity, Verdict.APPROVE, forged_binding)
        no_honest_verifiers = [
            forged_vote,
            self.attestation(self.challenger),
            self.attestation(self.governor),
        ]
        decision = self.evaluate(attestations=no_honest_verifiers)
        self.assertFalse(decision.authorized)
        self.assertIn("UNAUTHORIZED_ATTESTATION_IGNORED", decision.diagnostics)
        self.assertIn("VERIFIER_QUORUM_MISSING", decision.reason_codes)

    def test_unsafe_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            QuorumConfig(proposal_quorum=1, max_faulty_workers=1)

    def test_no_external_service_or_secret_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "decision.json"
            output.write_text(str(self.evaluate().to_dict()), encoding="utf-8")
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
