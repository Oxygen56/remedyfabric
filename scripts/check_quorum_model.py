#!/usr/bin/env python3
"""Exhaustively check the small RemedyFabric quorum state space."""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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
from remedyfabric.quorum import CandidateProposal, QuorumGate, patch_digest


def candidate(value: str) -> PatchCandidate:
    return PatchCandidate(
        "model-check",
        value,
        (FileEdit("src/target.py", "old", value, f"candidate {value}"),),
        1.0 if value == "safe" else 0.0,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run_id = "model-check-run"
    snapshot = canonical_digest({"snapshot": "before"})
    safe = candidate("safe")
    unsafe = candidate("unsafe")
    candidates = (safe, unsafe)

    workers = (
        AgentIdentity("worker-1", AgentRole.WORKER),
        AgentIdentity("worker-2", AgentRole.WORKER),
        AgentIdentity("worker-3", AgentRole.WORKER),
    )
    verifiers = (
        AgentIdentity("verifier-1", AgentRole.VERIFIER),
        AgentIdentity("verifier-2", AgentRole.VERIFIER),
    )
    challenger = AgentIdentity("challenger-1", AgentRole.CHALLENGER)
    governor = AgentIdentity("governor-1", AgentRole.GOVERNOR)
    release = AgentIdentity("release-1", AgentRole.RELEASE_MANAGER)
    controls = (*verifiers, challenger, governor)
    gate = QuorumGate((*workers, *controls, release))

    def proposal(identity, item):
        return CandidateProposal.issue(identity, run_id, snapshot, item)

    def vote(identity, item, verdict):
        kind = {
            AgentRole.VERIFIER: EvidenceKind.TEST,
            AgentRole.CHALLENGER: EvidenceKind.CHALLENGE,
            AgentRole.GOVERNOR: EvidenceKind.POLICY,
        }[identity.role]
        binding = EvidenceBinding(
            run_id,
            patch_digest(item),
            snapshot,
            kind,
            canonical_digest({"actor": identity.actor_id, "verdict": verdict.value}),
        )
        return Attestation.issue(identity, verdict, binding)

    violations: dict[str, list[dict[str, object]]] = {
        "single_worker_cannot_authorize": [],
        "worker_cannot_request_release": [],
        "rejection_cannot_be_overridden": [],
        "equivocation_cannot_authorize": [],
        "control_equivocation_cannot_authorize": [],
        "forged_or_replayed_evidence_cannot_authorize": [],
    }
    checked = 0
    authorized = 0
    worker_states = ("absent", "safe", "unsafe", "equivocate")
    control_states = ("absent", "approve", "reject")

    for worker_state in itertools.product(worker_states, repeat=len(workers)):
        proposals = []
        for identity, state in zip(workers, worker_state, strict=True):
            if state in {"safe", "equivocate"}:
                proposals.append(proposal(identity, safe))
            if state in {"unsafe", "equivocate"}:
                proposals.append(proposal(identity, unsafe))
        has_equivocation = "equivocate" in worker_state

        for control_state in itertools.product(control_states, repeat=len(controls)):
            has_rejection = "reject" in control_state
            for item in candidates:
                attestations = []
                for identity, state in zip(controls, control_state, strict=True):
                    if state != "absent":
                        verdict = Verdict.APPROVE if state == "approve" else Verdict.REJECT
                        attestations.append(vote(identity, item, verdict))
                for requester in (release, workers[0]):
                    decision = gate.evaluate(
                        run_id=run_id,
                        snapshot_digest=snapshot,
                        candidate=item,
                        proposals=proposals,
                        attestations=attestations,
                        requested_by=requester,
                    )
                    checked += 1
                    if not decision.authorized:
                        continue
                    authorized += 1
                    proposal_count = dict(decision.approval_counts)["worker-proposals"]
                    state = {
                        "worker_state": worker_state,
                        "control_state": control_state,
                        "candidate": item.diagnosis,
                        "requester": requester.actor_id,
                    }
                    if proposal_count < 2:
                        violations["single_worker_cannot_authorize"].append(state)
                    if requester.role is AgentRole.WORKER:
                        violations["worker_cannot_request_release"].append(state)
                    if has_rejection:
                        violations["rejection_cannot_be_overridden"].append(state)
                    if has_equivocation:
                        violations["equivocation_cannot_authorize"].append(state)

    honest_attestations = [vote(identity, safe, Verdict.APPROVE) for identity in controls]
    honest_proposals = [proposal(identity, safe) for identity in workers]
    for index, honest in enumerate(honest_attestations):
        rest = honest_attestations[:index] + honest_attestations[index + 1 :]
        for mode in (FaultMode.FORGE_EVIDENCE, FaultMode.REPLAY_EVIDENCE):
            faulty = inject_attestation_fault(honest, mode)
            decision = gate.evaluate(
                run_id=run_id,
                snapshot_digest=snapshot,
                candidate=safe,
                proposals=honest_proposals,
                attestations=[*faulty, *rest],
                requested_by=release,
            )
            checked += 1
            if decision.authorized:
                violations["forged_or_replayed_evidence_cannot_authorize"].append(
                    {"actor": honest.identity.actor_id, "fault": mode.value}
                )
        equivocation = inject_attestation_fault(
            honest,
            FaultMode.EQUIVOCATE,
            alternate_candidate_digest=patch_digest(unsafe),
        )
        decision = gate.evaluate(
            run_id=run_id,
            snapshot_digest=snapshot,
            candidate=safe,
            proposals=honest_proposals,
            attestations=[*equivocation, *rest],
            requested_by=release,
        )
        checked += 1
        if decision.authorized:
            violations["control_equivocation_cannot_authorize"].append(
                {"actor": honest.identity.actor_id, "fault": FaultMode.EQUIVOCATE.value}
            )

    properties = {
        name: {"holds": not examples, "violation_count": len(examples), "examples": examples[:3]}
        for name, examples in violations.items()
    }
    safe = all(result["holds"] for result in properties.values())
    output = {
        "schema_version": 1,
        "status": "safe-within-model" if safe else "violation-found",
        "checked_decisions": checked,
        "authorized_decisions": authorized,
        "state_space": {
            "workers": 3,
            "worker_states_each": list(worker_states),
            "verifiers": 2,
            "challengers": 1,
            "governors": 1,
            "control_states_each": list(control_states),
            "requesters": [release.actor_id, workers[0].actor_id],
            "candidates": 2,
        },
        "assumptions": [
            "membership and one-role-per-actor registration are trusted",
            "at most one repair worker is Byzantine-like",
            "control-plane roles are separately registered and authenticated by the runtime",
            "the checker does not model correlated implementation or provider failure",
            "SHA-256 fingerprints bind evidence but are not actor signatures",
            "this is exhaustive state exploration, not a formal BFT consensus proof",
        ],
        "properties": properties,
    }
    rendered = json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if safe else 1


if __name__ == "__main__":
    raise SystemExit(main())
