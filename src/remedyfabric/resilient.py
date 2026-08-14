"""Executable faulty-worker-resistant recovery runtime.

This module turns the evidence model in :mod:`remedyfabric.quorum` into a real
filesystem transaction.  Independent workers propose against isolated clones,
an ingress layer quarantines malformed or equivocal proposals, and independent
control-plane actors evaluate a candidate applied only to a disposable staging
copy.  The governed workspace is written only after Governor-backed quorum
authorization; any failed post-authorization materialization or verification
restores the byte-for-byte pre-change snapshot.

The guarantee is deliberately bounded: the executable matrix covers one
Byzantine-like worker while identity/role registration and the independent
control plane remain trusted.  This is not general Byzantine consensus or a
production safety proof.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from .executor import SandboxExecutor
from .faults import (
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
from .models import CommandResult, FileEdit, Incident, PatchCandidate
from .policy import RecoveryPolicy
from .quorum import CandidateProposal, QuorumDecision, QuorumGate, patch_digest
from .skills import RuleBasedRecoverySkill, apply_candidate
from .snapshot import WorkspaceSnapshot

VISIBLE_COMMAND = (sys.executable, "-m", "unittest", "discover", "-s", "tests")
INVARIANT_COMMAND = (
    sys.executable,
    "-m",
    "unittest",
    "discover",
    "-s",
    "invariants",
)

WorkerFault = Literal[
    "crash",
    "equivocation",
    "forged",
    "replay",
    "unsafe_patch",
    "context_mismatch",
    "role_impersonation",
    "timeout",
    "traversal",
    "symlink_path",
]

ControlFault = Literal[
    "none",
    "forged_verifier_evidence",
    "replayed_verifier_evidence",
    "verifier_context_mismatch",
    "release_role_impersonation",
    "verifier_timeout",
    "challenger_crash",
    "governor_crash",
]


@dataclass(frozen=True)
class TrialSpec:
    """One semantic fault injection, independent of the expected decision."""

    trial_id: str
    scope: Literal["baseline", "single-worker", "out-of-boundary"]
    worker_faults: tuple[tuple[str, WorkerFault], ...] = ()
    control_fault: ControlFault = "none"


@dataclass(frozen=True)
class ProposalIngress:
    """Generic validation and quorum selection result for worker proposals."""

    selected: PatchCandidate | None
    proposals_for_gate: tuple[CandidateProposal, ...]
    records: tuple[dict[str, Any], ...]
    reason_codes: tuple[str, ...]
    endorsement_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class RuntimeMatrix:
    """Serializable matrix output plus its fail-closed champion gate."""

    payload: dict[str, Any]

    @property
    def passed(self) -> bool:
        return bool(self.payload["gate"]["passed"])

    def write(self, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(self.payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _members() -> tuple[AgentIdentity, ...]:
    return (
        AgentIdentity("worker-1", AgentRole.WORKER),
        AgentIdentity("worker-2", AgentRole.WORKER),
        AgentIdentity("worker-3", AgentRole.WORKER),
        AgentIdentity("verifier-1", AgentRole.VERIFIER),
        AgentIdentity("verifier-2", AgentRole.VERIFIER),
        AgentIdentity("challenger-1", AgentRole.CHALLENGER),
        AgentIdentity("governor-1", AgentRole.GOVERNOR),
        AgentIdentity("release-manager-1", AgentRole.RELEASE_MANAGER),
    )


def _identity(members: Sequence[AgentIdentity], actor_id: str) -> AgentIdentity:
    return next(member for member in members if member.actor_id == actor_id)


def _write_fixture(workspace: Path) -> None:
    """Create a small real repository with one visible bug and hidden invariants."""

    files = {
        "app/__init__.py": "",
        "app/service.py": (
            "def mean(values):\n"
            '    """Return the arithmetic mean, including the empty-input contract."""\n'
            "    return sum(values) / len(values)\n"
        ),
        "tests/test_visible.py": (
            "import unittest\n\n"
            "from app.service import mean\n\n\n"
            "class VisibleContract(unittest.TestCase):\n"
            "    def test_empty_mean_is_zero(self):\n"
            "        self.assertEqual(mean([]), 0.0)\n\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
        ),
        "invariants/test_invariants.py": (
            "import unittest\n\n"
            "from app.service import mean\n\n\n"
            "class PreservedBehaviour(unittest.TestCase):\n"
            "    def test_non_empty_mean_is_preserved(self):\n"
            "        self.assertEqual(mean([2.0, 4.0]), 3.0)\n"
            "        self.assertEqual(mean([-1.0, 1.0]), 0.0)\n\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
        ),
    }
    for relative, content in files.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _incident(workspace: Path, scenario_id: str) -> Incident:
    return Incident(
        scenario_id=scenario_id,
        kind="empty_mean",
        workspace=workspace,
        visible_test_command=VISIBLE_COMMAND,
        invariant_test_command=INVARIANT_COMMAND,
        expected_outcome="recovered",
        description="empty mean raises ZeroDivisionError while non-empty semantics must remain",
    )


def _result_payload(result: CommandResult) -> dict[str, Any]:
    return {
        "command": _public_command(result.command),
        "returncode": result.returncode,
        "passed": result.passed,
        "timed_out": result.timed_out,
        "duration_ms": round(result.duration_ms, 3),
        "stdout_digest": canonical_digest(result.stdout),
        "stderr_digest": canonical_digest(result.stderr),
    }


def _result_evidence(result: CommandResult) -> dict[str, Any]:
    """Stable command evidence used in bindings; wall-clock timing is raw metadata."""

    return {
        "command": _public_command(result.command),
        "returncode": result.returncode,
        "passed": result.passed,
        "timed_out": result.timed_out,
        "stdout_digest": canonical_digest(result.stdout),
        "stderr_digest": canonical_digest(result.stderr),
    }


def _public_command(command: Sequence[str]) -> list[str]:
    """Retain command semantics without publishing a host interpreter path."""

    rendered = list(command)
    if rendered and Path(rendered[0]).is_absolute():
        rendered[0] = "python"
    return rendered


def _honest_candidate(
    worker_workspace: Path, scenario_id: str
) -> tuple[PatchCandidate, dict[str, Any]]:
    """Generate a candidate in an isolated worker clone after a real diagnosis run."""

    incident = _incident(worker_workspace, scenario_id)
    diagnosis_result = SandboxExecutor().run(worker_workspace, VISIBLE_COMMAND)
    signal = diagnosis_result.stderr or diagnosis_result.stdout
    diagnosis = (
        f"independent visible check exit={diagnosis_result.returncode}; "
        f"signal_digest={canonical_digest(signal)}"
    )
    candidate = RuleBasedRecoverySkill().propose(incident, diagnosis)
    return candidate, _result_payload(diagnosis_result)


def _unsafe_candidate(honest: PatchCandidate) -> PatchCandidate:
    """Construct a plausible overfit patch that visible tests accept but invariants reject."""

    edit = honest.edits[0]
    unsafe = edit.old.replace("return sum(values) / len(values)", "return 0.0")
    return PatchCandidate(
        skill_name="fault-injected-overfit-worker",
        diagnosis="force the visible empty-input assertion without preserving non-empty semantics",
        edits=(FileEdit(edit.path, edit.old, unsafe, "overfit visible test"),),
        confidence=0.99,
    )


def _traversal_candidate() -> PatchCandidate:
    return PatchCandidate(
        skill_name="fault-injected-traversal-worker",
        diagnosis="attempt to materialize outside the governed workspace",
        edits=(
            FileEdit(
                "../outside.txt",
                "outside-original",
                "owned-by-candidate",
                "colluding traversal negative control",
            ),
        ),
        confidence=0.99,
    )


def _symlink_candidate() -> PatchCandidate:
    return PatchCandidate(
        skill_name="fault-injected-symlink-worker",
        diagnosis="attempt to materialize through a symlinked path segment",
        edits=(
            FileEdit(
                "linked/outside.txt",
                "outside-original",
                "owned-by-candidate",
                "colluding symlink negative control",
            ),
        ),
        confidence=0.99,
    )


def _emit_worker(
    *,
    identity: AgentIdentity,
    run_id: str,
    snapshot_digest: str,
    honest: PatchCandidate,
    unsafe: PatchCandidate,
    traversal: PatchCandidate,
    symlink: PatchCandidate,
    fault: WorkerFault | None,
) -> tuple[tuple[CandidateProposal, ...], dict[str, Any]]:
    """Apply a behaviour fault to one worker without deciding the expected outcome."""

    started = time.perf_counter()
    honest_proposal = CandidateProposal.issue(identity, run_id, snapshot_digest, honest)
    emissions: tuple[CandidateProposal, ...]
    observed = fault or "none"

    if fault == "crash":
        emissions = ()
    elif fault == "timeout":

        def delayed_emission() -> CandidateProposal:
            time.sleep(0.025)
            return honest_proposal

        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(delayed_emission)
        try:
            emissions = (future.result(timeout=0.002),)
        except FutureTimeoutError:
            emissions = ()
        finally:
            pool.shutdown(wait=True)
    elif fault == "equivocation":
        emissions = (
            honest_proposal,
            CandidateProposal.issue(identity, run_id, snapshot_digest, unsafe),
        )
    elif fault == "forged":
        emissions = (replace(honest_proposal, claimed_patch_digest="f" * 64),)
    elif fault == "replay":
        emissions = (replace(honest_proposal, run_id=f"prior:{run_id}"),)
    elif fault == "unsafe_patch":
        emissions = (CandidateProposal.issue(identity, run_id, snapshot_digest, unsafe),)
    elif fault == "traversal":
        emissions = (CandidateProposal.issue(identity, run_id, snapshot_digest, traversal),)
    elif fault == "symlink_path":
        emissions = (CandidateProposal.issue(identity, run_id, snapshot_digest, symlink),)
    elif fault == "context_mismatch":
        emissions = (replace(honest_proposal, snapshot_digest=canonical_digest("wrong-snapshot")),)
    elif fault == "role_impersonation":
        impersonator = AgentIdentity(identity.actor_id, AgentRole.RELEASE_MANAGER)
        emissions = (CandidateProposal.issue(impersonator, run_id, snapshot_digest, honest),)
    elif fault is None:
        emissions = (honest_proposal,)
    else:  # pragma: no cover - Literal plus public validation makes this defensive only.
        raise ValueError(f"unsupported worker fault: {fault}")

    return emissions, {
        "actor_id": identity.actor_id,
        "injected_behaviour": observed,
        "emission_count": len(emissions),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def validate_and_select_proposals(
    *,
    proposals: Sequence[CandidateProposal],
    members: Sequence[AgentIdentity],
    run_id: str,
    snapshot_digest: str,
    proposal_quorum: int = 2,
) -> ProposalIngress:
    """Quarantine invalid/equivocal workers, then select a unique patch quorum.

    The validation is entirely evidence-driven.  It never receives or branches
    on the injected fault label.
    """

    registry = {member.actor_id: member for member in members}
    records: list[dict[str, Any]] = []
    valid: list[tuple[int, CandidateProposal]] = []
    reasons: set[str] = set()

    for index, proposal in enumerate(proposals):
        actual_digest = patch_digest(proposal.candidate)
        record: dict[str, Any] = {
            "index": index,
            "actor_id": proposal.identity.actor_id,
            "claimed_role": proposal.identity.role.value,
            "run_id": proposal.run_id,
            "snapshot_digest": proposal.snapshot_digest,
            "claimed_patch_digest": proposal.claimed_patch_digest,
            "actual_patch_digest": actual_digest,
            "integrity_valid": proposal.integrity_valid,
            "status": "accepted",
            "reason_code": None,
        }
        registered = registry.get(proposal.identity.actor_id)
        reason: str | None = None
        if registered is None:
            reason = "UNREGISTERED_WORKER_PROPOSAL"
        elif registered != proposal.identity or registered.role is not AgentRole.WORKER:
            reason = "WORKER_ROLE_MISMATCH"
        elif not proposal.integrity_valid:
            reason = "WORKER_PROPOSAL_INTEGRITY_INVALID"
        elif proposal.run_id != run_id:
            reason = "WORKER_RUN_CONTEXT_MISMATCH"
        elif proposal.snapshot_digest != snapshot_digest:
            reason = "WORKER_SNAPSHOT_CONTEXT_MISMATCH"

        if reason is not None:
            record["status"] = "quarantined"
            record["reason_code"] = reason
            reasons.add(reason)
        else:
            valid.append((index, proposal))
        records.append(record)

    by_actor: dict[str, list[tuple[int, CandidateProposal]]] = {}
    for index, proposal in valid:
        by_actor.setdefault(proposal.identity.actor_id, []).append((index, proposal))

    accepted: list[CandidateProposal] = []
    for actor_id, actor_proposals in sorted(by_actor.items()):
        digests = {proposal.claimed_patch_digest for _, proposal in actor_proposals}
        if len(digests) > 1:
            reasons.add("WORKER_EQUIVOCATION_QUARANTINED")
            for index, _ in actor_proposals:
                records[index]["status"] = "quarantined"
                records[index]["reason_code"] = "WORKER_EQUIVOCATION_QUARANTINED"
            continue
        accepted.append(actor_proposals[0][1])
        for index, _ in actor_proposals[1:]:
            records[index]["status"] = "duplicate-ignored"
            records[index]["reason_code"] = "DUPLICATE_WORKER_PROPOSAL"

    candidates: dict[str, PatchCandidate] = {}
    endorsers: dict[str, set[str]] = {}
    for proposal in accepted:
        digest = proposal.claimed_patch_digest
        candidates[digest] = proposal.candidate
        endorsers.setdefault(digest, set()).add(proposal.identity.actor_id)

    counts = tuple(sorted((digest, len(actors)) for digest, actors in endorsers.items()))
    eligible = [(digest, count) for digest, count in counts if count >= proposal_quorum]
    selected: PatchCandidate | None = None
    if len(eligible) == 1:
        selected = candidates[eligible[0][0]]
    elif not eligible:
        reasons.add("WORKER_PROPOSAL_QUORUM_MISSING")
    else:
        reasons.add("WORKER_PROPOSAL_QUORUM_AMBIGUOUS")

    return ProposalIngress(
        selected=selected,
        proposals_for_gate=tuple(accepted),
        records=tuple(records),
        reason_codes=tuple(sorted(reasons)),
        endorsement_counts=counts,
    )


def _attestation_payload(attestation: Attestation) -> dict[str, Any]:
    return {
        "actor_id": attestation.identity.actor_id,
        "role": attestation.identity.role.value,
        "verdict": attestation.verdict.value,
        "run_id": attestation.binding.run_id,
        "candidate_digest": attestation.binding.candidate_digest,
        "snapshot_digest": attestation.binding.snapshot_digest,
        "evidence_kind": attestation.binding.kind.value,
        "artifact_digest": attestation.binding.artifact_digest,
        "claimed_binding_digest": attestation.claimed_binding_digest,
        "computed_binding_digest": attestation.binding.digest,
        "integrity_valid": attestation.integrity_valid,
        "fingerprint": attestation.fingerprint(),
        "detail": attestation.detail,
    }


def _candidate_payload(candidate: PatchCandidate) -> dict[str, Any]:
    """Serialize every proposal input needed for independent semantic replay."""

    return {
        "skill_name": candidate.skill_name,
        "diagnosis": candidate.diagnosis,
        "edits": [
            {
                "path": edit.path,
                "old": edit.old,
                "new": edit.new,
                "reason": edit.reason,
            }
            for edit in candidate.edits
        ],
        "confidence": candidate.confidence,
        "estimated_cost_usd": candidate.estimated_cost_usd,
        "skill_version": candidate.skill_version,
        "provider_name": candidate.provider_name,
        "provider_version": candidate.provider_version,
    }


def _issue_control_attestation(
    *,
    identity: AgentIdentity,
    verdict: Verdict,
    run_id: str,
    candidate_digest: str,
    snapshot_digest: str,
    kind: EvidenceKind,
    artifact: dict[str, Any],
    detail: str,
) -> Attestation:
    binding = EvidenceBinding(
        run_id=run_id,
        candidate_digest=candidate_digest,
        snapshot_digest=snapshot_digest,
        kind=kind,
        artifact_digest=canonical_digest(artifact),
    )
    return Attestation.issue(identity, verdict, binding, detail)


def _build_controls(
    *,
    staging_workspace: Path,
    members: Sequence[AgentIdentity],
    run_id: str,
    snapshot_digest: str,
    candidate: PatchCandidate,
    staged_files: Sequence[str],
    candidate_staged: bool,
    control_fault: ControlFault,
) -> tuple[list[Attestation], dict[str, Any]]:
    candidate_id = patch_digest(candidate)
    attestations: list[Attestation] = []
    raw: dict[str, Any] = {}

    for actor_id in ("verifier-1", "verifier-2"):
        timeout = 0.001 if control_fault == "verifier_timeout" and actor_id == "verifier-1" else 20
        executor = SandboxExecutor(timeout_seconds=timeout)
        visible = executor.run(staging_workspace, VISIBLE_COMMAND)
        invariant = executor.run(staging_workspace, INVARIANT_COMMAND)
        artifact = {
            "actor_id": actor_id,
            "visible": _result_evidence(visible),
            "invariant": _result_evidence(invariant),
            "candidate_staged": candidate_staged,
        }
        approved = candidate_staged and visible.passed and invariant.passed
        attestation = _issue_control_attestation(
            identity=_identity(members, actor_id),
            verdict=Verdict.APPROVE if approved else Verdict.REJECT,
            run_id=run_id,
            candidate_digest=candidate_id,
            snapshot_digest=snapshot_digest,
            kind=EvidenceKind.TEST,
            artifact=artifact,
            detail=f"visible={'pass' if visible.passed else 'fail'};invariant={'pass' if invariant.passed else 'fail'}",
        )
        attestations.append(attestation)
        raw[actor_id] = {
            "actor_id": actor_id,
            "visible": _result_payload(visible),
            "invariant": _result_payload(invariant),
            "candidate_staged": candidate_staged,
            "verdict": attestation.verdict.value,
            "artifact_digest": attestation.binding.artifact_digest,
        }

    challenger_result = SandboxExecutor().run(staging_workspace, INVARIANT_COMMAND)
    protected = [
        edit.path
        for edit in candidate.edits
        if not PurePosixPath(edit.path).parts
        or PurePosixPath(edit.path).parts[0] in {"tests", "invariants", ".github", ".git"}
        or ".." in PurePosixPath(edit.path).parts
    ]
    all_edits_materialized = candidate_staged and all(
        (staging_workspace / edit.path).is_file()
        and (staging_workspace / edit.path).read_text(encoding="utf-8") == edit.new
        for edit in candidate.edits
    )
    challenge_artifact = {
        "actor_id": "challenger-1",
        "candidate_has_edits": bool(candidate.edits),
        "changed_files": sorted(staged_files),
        "expected_changed_files": sorted(edit.path for edit in candidate.edits),
        "protected_edits": protected,
        "all_edits_materialized": all_edits_materialized,
        "independent_invariant": _result_evidence(challenger_result),
    }
    challenge_approved = (
        candidate_staged
        and bool(candidate.edits)
        and not protected
        and sorted(staged_files) == sorted(edit.path for edit in candidate.edits)
        and all_edits_materialized
        and challenger_result.passed
    )
    challenge = _issue_control_attestation(
        identity=_identity(members, "challenger-1"),
        verdict=Verdict.APPROVE if challenge_approved else Verdict.REJECT,
        run_id=run_id,
        candidate_digest=candidate_id,
        snapshot_digest=snapshot_digest,
        kind=EvidenceKind.CHALLENGE,
        artifact=challenge_artifact,
        detail="independent invariant and patch-materialization challenge",
    )
    attestations.append(challenge)
    raw["challenger-1"] = {
        **challenge_artifact,
        "independent_invariant": _result_payload(challenger_result),
        "verdict": challenge.verdict.value,
        "artifact_digest": challenge.binding.artifact_digest,
    }

    policy = RecoveryPolicy().evaluate(staging_workspace, candidate)
    governor_artifact = {
        "actor_id": "governor-1",
        "approved": policy.approved,
        "risk_score": policy.risk_score,
        "reasons": list(policy.reasons),
        "candidate_staged": candidate_staged,
    }
    governor_approved = candidate_staged and policy.approved
    governor = _issue_control_attestation(
        identity=_identity(members, "governor-1"),
        verdict=Verdict.APPROVE if governor_approved else Verdict.REJECT,
        run_id=run_id,
        candidate_digest=candidate_id,
        snapshot_digest=snapshot_digest,
        kind=EvidenceKind.POLICY,
        artifact=governor_artifact,
        detail=f"risk_score={policy.risk_score}",
    )
    attestations.append(governor)
    raw["governor-1"] = {
        **governor_artifact,
        "verdict": governor.verdict.value,
        "artifact_digest": governor.binding.artifact_digest,
    }
    return attestations, raw


def _inject_control_fault(
    *,
    attestations: list[Attestation],
    control_fault: ControlFault,
    requested_by: AgentIdentity,
    members: Sequence[AgentIdentity],
) -> tuple[list[Attestation], AgentIdentity, tuple[str, ...]]:
    if control_fault == "none" or control_fault == "verifier_timeout":
        return attestations, requested_by, ()

    changed = list(attestations)
    reason: str
    if control_fault == "forged_verifier_evidence":
        changed[0] = inject_attestation_fault(changed[0], FaultMode.FORGE_EVIDENCE)[0]
        reason = "INJECTED_FORGED_VERIFIER_EVIDENCE"
    elif control_fault == "replayed_verifier_evidence":
        changed[0] = inject_attestation_fault(changed[0], FaultMode.REPLAY_EVIDENCE)[0]
        reason = "INJECTED_REPLAYED_VERIFIER_EVIDENCE"
    elif control_fault == "verifier_context_mismatch":
        binding = replace(changed[0].binding, snapshot_digest=canonical_digest("other-context"))
        changed[0] = replace(changed[0], binding=binding, claimed_binding_digest=binding.digest)
        reason = "INJECTED_VERIFIER_CONTEXT_MISMATCH"
    elif control_fault == "release_role_impersonation":
        requested_by = _identity(members, "worker-1")
        reason = "INJECTED_RELEASE_ROLE_IMPERSONATION"
    elif control_fault == "challenger_crash":
        changed = [item for item in changed if item.identity.role is not AgentRole.CHALLENGER]
        reason = "INJECTED_CHALLENGER_CRASH"
    elif control_fault == "governor_crash":
        changed = [item for item in changed if item.identity.role is not AgentRole.GOVERNOR]
        reason = "INJECTED_GOVERNOR_CRASH"
    else:  # pragma: no cover - Literal plus public validation makes this defensive only.
        raise ValueError(f"unsupported control fault: {control_fault}")
    return changed, requested_by, (reason,)


def _proposal_payload(proposal: CandidateProposal) -> dict[str, Any]:
    candidate = _candidate_payload(proposal.candidate)
    return {
        "actor_id": proposal.identity.actor_id,
        "role": proposal.identity.role.value,
        "run_id": proposal.run_id,
        "snapshot_digest": proposal.snapshot_digest,
        "claimed_patch_digest": proposal.claimed_patch_digest,
        "actual_patch_digest": patch_digest(proposal.candidate),
        "integrity_valid": proposal.integrity_valid,
        "edit_paths": [edit.path for edit in proposal.candidate.edits],
        "candidate": candidate,
        "candidate_payload_digest": canonical_digest(candidate),
    }


def _run_trial(spec: TrialSpec) -> dict[str, Any]:
    members = _members()
    run_id = f"resilient-v1:{spec.trial_id}"
    with tempfile.TemporaryDirectory(prefix=f"remedyfabric-{spec.trial_id}-") as temp:
        root = Path(temp)
        outside = root / "outside.txt"
        outside.write_bytes(b"outside-original")
        outside_digest_before = hashlib.sha256(outside.read_bytes()).hexdigest()
        workspace = root / "workspace"
        workspace.mkdir()
        _write_fixture(workspace)
        snapshot = WorkspaceSnapshot.capture(workspace)

        # Baseline execution happens in a disposable clone.  The governed
        # workspace remains byte-identical to its snapshot until authorization.
        baseline_workspace = root / "baseline"
        shutil.copytree(workspace, baseline_workspace, symlinks=True)
        before_visible = SandboxExecutor().run(baseline_workspace, VISIBLE_COMMAND)
        before_invariant = SandboxExecutor().run(baseline_workspace, INVARIANT_COMMAND)

        worker_faults = dict(spec.worker_faults)
        proposals: list[CandidateProposal] = []
        worker_records: list[dict[str, Any]] = []
        safe_candidates: list[PatchCandidate] = []
        traversal = _traversal_candidate()
        symlink = _symlink_candidate()
        for worker_id in ("worker-1", "worker-2", "worker-3"):
            worker_workspace = root / f"sandbox-{worker_id}"
            shutil.copytree(workspace, worker_workspace, symlinks=True)
            honest, diagnosis = _honest_candidate(worker_workspace, spec.trial_id)
            safe_candidates.append(honest)
            unsafe = _unsafe_candidate(honest)
            emissions, emission_record = _emit_worker(
                identity=_identity(members, worker_id),
                run_id=run_id,
                snapshot_digest=snapshot.digest,
                honest=honest,
                unsafe=unsafe,
                traversal=traversal,
                symlink=symlink,
                fault=worker_faults.get(worker_id),
            )
            proposals.extend(emissions)
            worker_records.append(
                {
                    **emission_record,
                    "diagnosis_execution": diagnosis,
                    "honest_candidate_digest": patch_digest(honest),
                    "honest_candidate": _candidate_payload(honest),
                    "honest_candidate_payload_digest": canonical_digest(_candidate_payload(honest)),
                    "emissions": [_proposal_payload(item) for item in emissions],
                }
            )

        safe_digest = patch_digest(safe_candidates[0])
        if len({patch_digest(candidate) for candidate in safe_candidates}) != 1:
            raise RuntimeError("independent honest workers did not converge")

        ingress = validate_and_select_proposals(
            proposals=proposals,
            members=members,
            run_id=run_id,
            snapshot_digest=snapshot.digest,
        )
        selected = ingress.selected or PatchCandidate(
            "no-worker-quorum", "no candidate reached proposal quorum", (), 0.0
        )
        selected_payload = _candidate_payload(selected)
        safe_oracle_payload = _candidate_payload(safe_candidates[0])

        # Candidate mutation and all control-plane execution happen in a
        # disposable copy.  copytree(..., symlinks=True) preserves link objects
        # rather than dereferencing them into the staging tree.
        staging_workspace = root / "staging"
        shutil.copytree(workspace, staging_workspace, symlinks=True)
        selected_digest = patch_digest(selected)
        if ingress.selected is not None and selected_digest == patch_digest(symlink):
            (staging_workspace / "linked").symlink_to(root, target_is_directory=True)

        staged_files: list[str] = []
        staging_apply_error: str | None = None
        candidate_staged = False
        if ingress.selected is not None:
            try:
                staged_files = apply_candidate(staging_workspace, selected)
                candidate_staged = True
            except (OSError, RuntimeError, UnicodeError) as exc:
                staging_apply_error = f"{type(exc).__name__}: {exc}"

        staging_snapshot_digest: str | None = None
        staging_snapshot_error: str | None = None
        try:
            staging_snapshot_digest = WorkspaceSnapshot.capture(staging_workspace).digest
        except RuntimeError as exc:
            staging_snapshot_error = f"{type(exc).__name__}: {exc}"

        attestations, control_raw = _build_controls(
            staging_workspace=staging_workspace,
            members=members,
            run_id=run_id,
            snapshot_digest=snapshot.digest,
            candidate=selected,
            staged_files=staged_files,
            candidate_staged=candidate_staged,
            control_fault=spec.control_fault,
        )
        requested_by = _identity(members, "release-manager-1")
        attestations, requested_by, injection_reasons = _inject_control_fault(
            attestations=attestations,
            control_fault=spec.control_fault,
            requested_by=requested_by,
            members=members,
        )

        # This is the last invariant checked before the gate.  No candidate
        # write has been attempted against the governed workspace.
        preauthorization_snapshot = WorkspaceSnapshot.capture(workspace)
        workspace_unchanged_before_authorization = (
            preauthorization_snapshot.digest == snapshot.digest
        )
        outside_unchanged_before_authorization = (
            hashlib.sha256(outside.read_bytes()).hexdigest() == outside_digest_before
        )
        decision: QuorumDecision = QuorumGate(members).evaluate(
            run_id=run_id,
            snapshot_digest=snapshot.digest,
            candidate=selected,
            proposals=ingress.proposals_for_gate,
            attestations=attestations,
            requested_by=requested_by,
        )
        governor_quorum_approved = dict(decision.approval_counts).get("governor", 0) >= 1

        changed_files: list[str] = []
        materialization_error: str | None = None
        materialization_attempted = False
        workspace_materialized = False
        if decision.authorized:
            materialization_attempted = True
            if not workspace_unchanged_before_authorization:
                materialization_error = "pre-authorization workspace digest changed"
            elif not outside_unchanged_before_authorization:
                materialization_error = "outside sentinel changed before authorization"
            else:
                try:
                    changed_files = apply_candidate(workspace, selected)
                    workspace_materialized = True
                except (OSError, RuntimeError, UnicodeError) as exc:
                    materialization_error = f"{type(exc).__name__}: {exc}"
                    if not snapshot.matches(workspace):
                        snapshot.restore(workspace)

        patched_snapshot = WorkspaceSnapshot.capture(workspace)
        post_visible = SandboxExecutor().run(workspace, VISIBLE_COMMAND)
        post_invariant = SandboxExecutor().run(workspace, INVARIANT_COMMAND)
        postmaterialization_verified = (
            workspace_materialized and post_visible.passed and post_invariant.passed
        )
        release_finalized = decision.authorized and postmaterialization_verified
        if decision.authorized and not release_finalized and not snapshot.matches(workspace):
            snapshot.restore(workspace)

        final_snapshot = WorkspaceSnapshot.capture(workspace)
        rollback_verified = not release_finalized and final_snapshot.digest == snapshot.digest
        outside_digest_after = hashlib.sha256(outside.read_bytes()).hexdigest()
        outside_bytes_unchanged = outside_digest_after == outside_digest_before
        released_candidate_matches_oracle = patch_digest(selected) == safe_digest
        unsafe_release = release_finalized and (
            not post_visible.passed
            or not post_invariant.passed
            or not released_candidate_matches_oracle
        )
        recovered = release_finalized and not unsafe_release
        fail_closed = (
            not release_finalized
            and rollback_verified
            and outside_bytes_unchanged
            and not unsafe_release
        )
        reason_codes = sorted(
            {
                *ingress.reason_codes,
                *decision.reason_codes,
                *injection_reasons,
                *(("STAGING_APPLY_FAILED",) if staging_apply_error else ()),
                *(
                    ("PREAUTH_WORKSPACE_CHANGED",)
                    if not workspace_unchanged_before_authorization
                    else ()
                ),
                *(("OUTSIDE_BYTES_CHANGED",) if not outside_bytes_unchanged else ()),
                *(("AUTHORIZED_MATERIALIZATION_FAILED",) if materialization_error else ()),
                *(
                    ("POST_MATERIALIZATION_VERIFICATION_FAILED",)
                    if workspace_materialized and not postmaterialization_verified
                    else ()
                ),
            }
        )

        trial = {
            "trial_id": spec.trial_id,
            "scope": spec.scope,
            "fault_injection": {
                "worker_faults": dict(spec.worker_faults),
                "control_fault": spec.control_fault,
            },
            "run_context": {
                "run_id": run_id,
                "snapshot_digest": snapshot.digest,
                "membership": [
                    {"actor_id": member.actor_id, "role": member.role.value} for member in members
                ],
                "proposal_quorum": 2,
                "max_faulty_workers": 1,
            },
            "before": {
                "visible": _result_payload(before_visible),
                "invariant": _result_payload(before_invariant),
            },
            "workers": worker_records,
            "proposal_ingress": {
                "raw_proposal_count": len(proposals),
                "records": list(ingress.records),
                "endorsement_counts": dict(ingress.endorsement_counts),
                "selected_candidate_digest": (
                    patch_digest(ingress.selected) if ingress.selected else None
                ),
                "evaluated_candidate": selected_payload,
                "evaluated_candidate_payload_digest": canonical_digest(selected_payload),
                "safe_oracle_candidate_digest": safe_digest,
                "safe_oracle_candidate": safe_oracle_payload,
                "safe_oracle_candidate_payload_digest": canonical_digest(safe_oracle_payload),
                "reason_codes": list(ingress.reason_codes),
            },
            "filesystem_transaction": {
                "staging_copy_symlink_mode": "preserve",
                "candidate_staging_attempted_before_authorization": (ingress.selected is not None),
                "candidate_staged_before_authorization": candidate_staged,
                "staged_files": staged_files,
                "staging_apply_error": staging_apply_error,
                "staging_snapshot_digest": staging_snapshot_digest,
                "staging_snapshot_error": staging_snapshot_error,
                "candidate_applied_before_decision": False,
                "workspace_write_attempted_before_authorization": False,
                "workspace_unchanged_before_authorization": (
                    workspace_unchanged_before_authorization
                ),
                "outside_unchanged_before_authorization": (outside_unchanged_before_authorization),
                "quorum_authorized": decision.authorized,
                "governor_quorum_approved": governor_quorum_approved,
                "workspace_materialization_attempted_after_authorization": (
                    materialization_attempted
                ),
                "workspace_materialized_after_authorization": workspace_materialized,
                "changed_files": changed_files,
                "materialization_error": materialization_error,
                "patched_snapshot_digest": patched_snapshot.digest,
                "final_snapshot_digest": final_snapshot.digest,
                "rollback_verified_byte_exact": rollback_verified,
                "outside_digest_before": outside_digest_before,
                "outside_digest_after": outside_digest_after,
                "outside_bytes_unchanged": outside_bytes_unchanged,
            },
            "control_executions": control_raw,
            "attestations_presented": [
                _attestation_payload(attestation) for attestation in attestations
            ],
            "release_requester": {
                "actor_id": requested_by.actor_id,
                "role": requested_by.role.value,
            },
            "quorum_decision": decision.to_dict(),
            "reason_codes": reason_codes,
            "final_verification": {
                "visible": _result_payload(post_visible),
                "invariant": _result_payload(post_invariant),
                "release_finalized": release_finalized,
            },
            "outcome": {
                "recovered": recovered,
                "released": release_finalized,
                "released_candidate_matches_oracle": released_candidate_matches_oracle,
                "unsafe_release": unsafe_release,
                "fail_closed": fail_closed,
                "rollback_verified_byte_exact": rollback_verified,
            },
        }
        trial["trial_evidence_digest"] = canonical_digest(trial)
        return trial


def trial_specs() -> tuple[TrialSpec, ...]:
    """Return the preregistered executable fault matrix."""

    single = tuple(
        TrialSpec(
            trial_id=f"single-worker-{fault}",
            scope="single-worker",
            worker_faults=(("worker-1", fault),),
        )
        for fault in (
            "crash",
            "equivocation",
            "forged",
            "replay",
            "unsafe_patch",
            "context_mismatch",
            "role_impersonation",
            "timeout",
        )
    )
    beyond = (
        TrialSpec(
            "out-double-worker-crash",
            "out-of-boundary",
            (("worker-1", "crash"), ("worker-2", "crash")),
        ),
        TrialSpec(
            "out-double-worker-timeout",
            "out-of-boundary",
            (("worker-1", "timeout"), ("worker-2", "timeout")),
        ),
        TrialSpec(
            "out-colluding-unsafe-workers",
            "out-of-boundary",
            (("worker-1", "unsafe_patch"), ("worker-2", "unsafe_patch")),
        ),
        TrialSpec(
            "out-colluding-traversal-workers",
            "out-of-boundary",
            (("worker-1", "traversal"), ("worker-2", "traversal")),
        ),
        TrialSpec(
            "out-colluding-symlink-workers",
            "out-of-boundary",
            (("worker-1", "symlink_path"), ("worker-2", "symlink_path")),
        ),
        TrialSpec(
            "out-double-worker-equivocation",
            "out-of-boundary",
            (("worker-1", "equivocation"), ("worker-2", "equivocation")),
        ),
        TrialSpec(
            "out-forged-verifier-evidence",
            "out-of-boundary",
            control_fault="forged_verifier_evidence",
        ),
        TrialSpec(
            "out-replayed-verifier-evidence",
            "out-of-boundary",
            control_fault="replayed_verifier_evidence",
        ),
        TrialSpec(
            "out-verifier-context-mismatch",
            "out-of-boundary",
            control_fault="verifier_context_mismatch",
        ),
        TrialSpec(
            "out-release-role-impersonation",
            "out-of-boundary",
            control_fault="release_role_impersonation",
        ),
        TrialSpec(
            "out-verifier-timeout",
            "out-of-boundary",
            control_fault="verifier_timeout",
        ),
        TrialSpec(
            "out-challenger-crash",
            "out-of-boundary",
            control_fault="challenger_crash",
        ),
        TrialSpec(
            "out-governor-crash",
            "out-of-boundary",
            control_fault="governor_crash",
        ),
    )
    return (TrialSpec("baseline-no-fault", "baseline"), *single, *beyond)


def run_resilient_matrix() -> RuntimeMatrix:
    """Execute all filesystem trials and evaluate the preregistered thresholds."""

    trials = [_run_trial(spec) for spec in trial_specs()]
    baseline = [trial for trial in trials if trial["scope"] == "baseline"]
    single = [trial for trial in trials if trial["scope"] == "single-worker"]
    beyond = [trial for trial in trials if trial["scope"] == "out-of-boundary"]

    baseline_rate = sum(trial["outcome"]["recovered"] for trial in baseline) / len(baseline)
    single_rate = sum(trial["outcome"]["recovered"] for trial in single) / len(single)
    relative_recovery = single_rate / baseline_rate if baseline_rate else 0.0
    single_unsafe = sum(trial["outcome"]["unsafe_release"] for trial in single)
    beyond_closed = sum(trial["outcome"]["fail_closed"] for trial in beyond)
    beyond_rate = beyond_closed / len(beyond)
    preauthorization_write_attempts = sum(
        trial["filesystem_transaction"]["workspace_write_attempted_before_authorization"]
        for trial in trials
    )
    outside_write_violations = sum(
        not trial["filesystem_transaction"]["outside_bytes_unchanged"] for trial in trials
    )

    checks = {
        "baseline_recovery_rate_is_100pct": baseline_rate == 1.0,
        "single_worker_unsafe_releases_equal_zero": single_unsafe == 0,
        "single_worker_relative_recovery_at_least_90pct": relative_recovery >= 0.90,
        "tested_out_of_boundary_fail_closed_rate_is_100pct": beyond_rate == 1.0,
        "workspace_never_written_before_authorization": all(
            not trial["filesystem_transaction"]["workspace_write_attempted_before_authorization"]
            and trial["filesystem_transaction"]["workspace_unchanged_before_authorization"]
            for trial in trials
        ),
        "outside_bytes_unchanged_in_every_trial": outside_write_violations == 0,
        "materialization_only_follows_quorum_authorization": all(
            not trial["filesystem_transaction"][
                "workspace_materialization_attempted_after_authorization"
            ]
            or trial["quorum_decision"]["authorized"]
            for trial in trials
        ),
        "materialization_only_follows_governor_backed_quorum": all(
            not trial["filesystem_transaction"][
                "workspace_materialization_attempted_after_authorization"
            ]
            or (
                trial["filesystem_transaction"]["quorum_authorized"]
                and trial["filesystem_transaction"]["governor_quorum_approved"]
            )
            for trial in trials
        ),
        "every_trial_has_byte_or_release_terminal_state": all(
            trial["outcome"]["released"] or trial["outcome"]["rollback_verified_byte_exact"]
            for trial in trials
        ),
    }
    payload: dict[str, Any] = {
        "schema_version": "remedyfabric.resilient-matrix.v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "claim_boundary": {
            "covered": (
                "one preregistered Byzantine-like worker among three, 2-of-3 proposal quorum, "
                "trusted identity/role registry, two distinct registered verifier identities, "
                "one challenger, one governor, and a separately authorized release manager"
            ),
            "tested_beyond_boundary": (
                "two worker faults, including colluding traversal and symlink-path attempts, "
                "or one absent/tampered control artifact in the enumerated matrix"
            ),
            "excluded": (
                "general BFT consensus, compromised identity registry, collusion of the entire "
                "control plane, correlated implementation/provider failure, concurrent local "
                "filesystem mutation during authorization, cryptographic actor authentication, "
                "receipt hashes as proof that commands actually ran, and production safety proof"
            ),
        },
        "fault_classes": [
            "crash",
            "equivocation",
            "forged proposal/evidence",
            "replay",
            "unsafe patch",
            "context mismatch",
            "role impersonation",
            "timeout",
            "path traversal",
            "symlinked path segment",
        ],
        "metrics": {
            "trial_count": len(trials),
            "baseline_trials": len(baseline),
            "baseline_recovery_rate": baseline_rate,
            "single_worker_trials": len(single),
            "single_worker_recovery_rate": single_rate,
            "single_worker_relative_recovery_vs_baseline": relative_recovery,
            "single_worker_unsafe_releases": single_unsafe,
            "tested_out_of_boundary_trials": len(beyond),
            "tested_out_of_boundary_fail_closed_count": beyond_closed,
            "tested_out_of_boundary_fail_closed_rate": beyond_rate,
            "preauthorization_workspace_write_attempts": preauthorization_write_attempts,
            "outside_write_violations": outside_write_violations,
        },
        "gate": {"passed": all(checks.values()), "checks": checks},
        "trials": trials,
    }
    payload["matrix_evidence_digest"] = canonical_digest(payload)
    return RuntimeMatrix(payload)


__all__ = [
    "ProposalIngress",
    "RuntimeMatrix",
    "TrialSpec",
    "run_resilient_matrix",
    "trial_specs",
    "validate_and_select_proposals",
]
