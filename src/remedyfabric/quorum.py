"""Evidence-bound, role-separated release quorum for autonomous recovery."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from .faults import (
    AgentIdentity,
    AgentRole,
    Attestation,
    EvidenceKind,
    Verdict,
    canonical_digest,
    is_sha256,
)
from .models import PatchCandidate


class RecoveryAction(str, Enum):
    RELEASE = "release"
    ROLLBACK = "rollback"


EXPECTED_EVIDENCE = {
    AgentRole.VERIFIER: EvidenceKind.TEST,
    AgentRole.CHALLENGER: EvidenceKind.CHALLENGE,
    AgentRole.GOVERNOR: EvidenceKind.POLICY,
}


def patch_digest(candidate: PatchCandidate) -> str:
    """Identify executable patch content and its producing contract version."""

    return canonical_digest(
        {
            "skill_name": candidate.skill_name,
            "skill_version": candidate.skill_version,
            "provider_name": candidate.provider_name,
            "provider_version": candidate.provider_version,
            "edits": [
                {
                    "path": edit.path,
                    "old": edit.old,
                    "new": edit.new,
                }
                for edit in candidate.edits
            ],
        }
    )


@dataclass(frozen=True)
class CandidateProposal:
    """One registered worker identity's typed PatchCandidate proposal."""

    identity: AgentIdentity
    run_id: str
    snapshot_digest: str
    candidate: PatchCandidate
    claimed_patch_digest: str

    @classmethod
    def issue(
        cls,
        identity: AgentIdentity,
        run_id: str,
        snapshot_digest: str,
        candidate: PatchCandidate,
    ) -> CandidateProposal:
        return cls(identity, run_id, snapshot_digest, candidate, patch_digest(candidate))

    @property
    def integrity_valid(self) -> bool:
        return (
            self.identity.role is AgentRole.WORKER
            and bool(self.run_id)
            and is_sha256(self.snapshot_digest)
            and self.claimed_patch_digest == patch_digest(self.candidate)
        )


@dataclass(frozen=True)
class QuorumConfig:
    """Thresholds for the bounded single-fault worker model."""

    proposal_quorum: int = 2
    verifier_quorum: int = 2
    challenger_quorum: int = 1
    governor_quorum: int = 1
    max_faulty_workers: int = 1

    def __post_init__(self) -> None:
        thresholds = (
            self.proposal_quorum,
            self.verifier_quorum,
            self.challenger_quorum,
            self.governor_quorum,
        )
        if any(value < 1 for value in thresholds):
            raise ValueError("all quorum thresholds must be positive")
        if self.max_faulty_workers < 0:
            raise ValueError("max_faulty_workers cannot be negative")
        if self.proposal_quorum <= self.max_faulty_workers:
            raise ValueError("proposal_quorum must exceed the faulty-worker bound")


@dataclass(frozen=True)
class QuorumDecision:
    authorized: bool
    action: RecoveryAction
    candidate_digest: str
    approval_counts: tuple[tuple[str, int], ...]
    reason_codes: tuple[str, ...]
    diagnostics: tuple[str, ...]
    receipt_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "authorized": self.authorized,
            "action": self.action.value,
            "candidate_digest": self.candidate_digest,
            "approval_counts": dict(self.approval_counts),
            "reason_codes": list(self.reason_codes),
            "diagnostics": list(self.diagnostics),
            "receipt_digest": self.receipt_digest,
        }


class QuorumGate:
    """Authorize release only after independent proposal and control quorums.

    Membership is fixed for one gate.  An actor has exactly one role, duplicate
    votes never increase quorum, and conflicting evidence from a registered
    control actor forces rollback.
    """

    def __init__(
        self,
        members: Iterable[AgentIdentity],
        config: QuorumConfig | None = None,
    ) -> None:
        member_list = tuple(members)
        member_ids = [member.actor_id for member in member_list]
        if len(member_ids) != len(set(member_ids)):
            raise ValueError("membership contains duplicate actor_id values")
        self.members = {member.actor_id: member for member in member_list}
        self.config = config or QuorumConfig()

    def evaluate(
        self,
        *,
        run_id: str,
        snapshot_digest: str,
        candidate: PatchCandidate,
        proposals: Sequence[CandidateProposal],
        attestations: Sequence[Attestation],
        requested_by: AgentIdentity,
    ) -> QuorumDecision:
        candidate_id = patch_digest(candidate)
        blocking: set[str] = set()
        diagnostics: set[str] = set()

        registered_requester = self.members.get(requested_by.actor_id)
        if (
            registered_requester is None
            or registered_requester != requested_by
            or requested_by.role is not AgentRole.RELEASE_MANAGER
        ):
            blocking.add("REQUESTER_NOT_RELEASE_MANAGER")

        if not run_id or not is_sha256(snapshot_digest):
            blocking.add("INVALID_RUN_CONTEXT")

        proposal_patches: dict[str, set[str]] = {}
        endorsers: set[str] = set()
        for proposal in proposals:
            registered = self.members.get(proposal.identity.actor_id)
            if registered is None:
                diagnostics.add("UNREGISTERED_PROPOSAL_IGNORED")
                continue
            if registered.role is not AgentRole.WORKER or proposal.identity != registered:
                diagnostics.add("UNAUTHORIZED_PROPOSAL_IGNORED")
                continue
            proposal_patches.setdefault(registered.actor_id, set()).add(
                proposal.claimed_patch_digest
            )
            if not proposal.integrity_valid:
                blocking.add("INVALID_PROPOSAL_INTEGRITY")
                continue
            if proposal.run_id != run_id or proposal.snapshot_digest != snapshot_digest:
                blocking.add("PROPOSAL_CONTEXT_MISMATCH")
                continue
            if proposal.claimed_patch_digest == candidate_id:
                endorsers.add(registered.actor_id)

        if any(len(digests) > 1 for digests in proposal_patches.values()):
            blocking.add("WORKER_EQUIVOCATION")
        if len(endorsers) < self.config.proposal_quorum:
            blocking.add("PROPOSAL_QUORUM_MISSING")

        approvals: dict[AgentRole, set[str]] = {
            AgentRole.VERIFIER: set(),
            AgentRole.CHALLENGER: set(),
            AgentRole.GOVERNOR: set(),
        }
        observed: dict[str, set[str]] = {}
        for attestation in attestations:
            registered = self.members.get(attestation.identity.actor_id)
            if registered is None:
                diagnostics.add("UNREGISTERED_ATTESTATION_IGNORED")
                continue
            if registered != attestation.identity or registered.role not in EXPECTED_EVIDENCE:
                diagnostics.add("UNAUTHORIZED_ATTESTATION_IGNORED")
                continue

            observed.setdefault(registered.actor_id, set()).add(attestation.fingerprint())
            if not attestation.integrity_valid:
                blocking.add("INVALID_ATTESTATION_INTEGRITY")
                continue
            binding = attestation.binding
            if (
                binding.run_id != run_id
                or binding.snapshot_digest != snapshot_digest
                or binding.candidate_digest != candidate_id
            ):
                blocking.add("ATTESTATION_CONTEXT_MISMATCH")
                continue
            if binding.kind is not EXPECTED_EVIDENCE[registered.role]:
                blocking.add("EVIDENCE_KIND_MISMATCH")
                continue
            if attestation.verdict is Verdict.REJECT:
                blocking.add("CONTROL_REJECTION")
            elif attestation.verdict is Verdict.APPROVE:
                approvals[registered.role].add(registered.actor_id)

        if any(len(fingerprints) > 1 for fingerprints in observed.values()):
            blocking.add("CONTROL_EQUIVOCATION")

        required = {
            AgentRole.VERIFIER: self.config.verifier_quorum,
            AgentRole.CHALLENGER: self.config.challenger_quorum,
            AgentRole.GOVERNOR: self.config.governor_quorum,
        }
        for role, threshold in required.items():
            if len(approvals[role]) < threshold:
                blocking.add(f"{role.value.upper().replace('-', '_')}_QUORUM_MISSING")

        counts = (
            ("worker-proposals", len(endorsers)),
            ("verifier", len(approvals[AgentRole.VERIFIER])),
            ("challenger", len(approvals[AgentRole.CHALLENGER])),
            ("governor", len(approvals[AgentRole.GOVERNOR])),
        )
        reason_codes = tuple(sorted(blocking))
        diagnostic_codes = tuple(sorted(diagnostics))
        authorized = not reason_codes
        action = RecoveryAction.RELEASE if authorized else RecoveryAction.ROLLBACK
        receipt_digest = canonical_digest(
            {
                "run_id": run_id,
                "snapshot_digest": snapshot_digest,
                "candidate_digest": candidate_id,
                "requested_by": requested_by.actor_id,
                "authorized": authorized,
                "action": action.value,
                "approval_counts": dict(counts),
                "reason_codes": reason_codes,
                "diagnostics": diagnostic_codes,
            }
        )
        return QuorumDecision(
            authorized=authorized,
            action=action,
            candidate_digest=candidate_id,
            approval_counts=counts,
            reason_codes=reason_codes,
            diagnostics=diagnostic_codes,
            receipt_digest=receipt_digest,
        )
