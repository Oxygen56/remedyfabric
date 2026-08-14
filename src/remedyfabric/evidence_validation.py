"""Semantic validation for every artifact used by the champion gate.

Hashes freeze bytes.  These validators independently recompute the headline
facts from the underlying receipts so a self-reported ``passed`` flag is never
enough to authorize a public claim.
"""

from __future__ import annotations

import hashlib
import json
import math
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from .faults import (
    AgentIdentity,
    AgentRole,
    Attestation,
    EvidenceBinding,
    EvidenceKind,
    FaultMode,
    Verdict,
    inject_attestation_fault,
    is_sha256,
)
from .models import FileEdit, PatchCandidate
from .policy import SECRET_PATTERN
from .quorum import CandidateProposal, QuorumGate, patch_digest
from .resilient import validate_and_select_proposals

EXPECTED_MEMBERSHIP = (
    ("worker-1", "worker"),
    ("worker-2", "worker"),
    ("worker-3", "worker"),
    ("verifier-1", "verifier"),
    ("verifier-2", "verifier"),
    ("challenger-1", "challenger"),
    ("governor-1", "governor"),
    ("release-manager-1", "release-manager"),
)
EXPECTED_VISIBLE_COMMAND = ["python", "-m", "unittest", "discover", "-s", "tests"]
EXPECTED_INVARIANT_COMMAND = [
    "python",
    "-m",
    "unittest",
    "discover",
    "-s",
    "invariants",
]
EXPECTED_RESILIENT_TRIAL_SPECS: dict[str, dict[str, Any]] = {
    "baseline-no-fault": {"scope": "baseline", "workers": {}, "control": "none"},
    "single-worker-crash": {
        "scope": "single-worker",
        "workers": {"worker-1": "crash"},
        "control": "none",
    },
    "single-worker-equivocation": {
        "scope": "single-worker",
        "workers": {"worker-1": "equivocation"},
        "control": "none",
    },
    "single-worker-forged": {
        "scope": "single-worker",
        "workers": {"worker-1": "forged"},
        "control": "none",
    },
    "single-worker-replay": {
        "scope": "single-worker",
        "workers": {"worker-1": "replay"},
        "control": "none",
    },
    "single-worker-unsafe_patch": {
        "scope": "single-worker",
        "workers": {"worker-1": "unsafe_patch"},
        "control": "none",
    },
    "single-worker-context_mismatch": {
        "scope": "single-worker",
        "workers": {"worker-1": "context_mismatch"},
        "control": "none",
    },
    "single-worker-role_impersonation": {
        "scope": "single-worker",
        "workers": {"worker-1": "role_impersonation"},
        "control": "none",
    },
    "single-worker-timeout": {
        "scope": "single-worker",
        "workers": {"worker-1": "timeout"},
        "control": "none",
    },
    "out-double-worker-crash": {
        "scope": "out-of-boundary",
        "workers": {"worker-1": "crash", "worker-2": "crash"},
        "control": "none",
    },
    "out-double-worker-timeout": {
        "scope": "out-of-boundary",
        "workers": {"worker-1": "timeout", "worker-2": "timeout"},
        "control": "none",
    },
    "out-colluding-unsafe-workers": {
        "scope": "out-of-boundary",
        "workers": {"worker-1": "unsafe_patch", "worker-2": "unsafe_patch"},
        "control": "none",
    },
    "out-colluding-traversal-workers": {
        "scope": "out-of-boundary",
        "workers": {"worker-1": "traversal", "worker-2": "traversal"},
        "control": "none",
    },
    "out-colluding-symlink-workers": {
        "scope": "out-of-boundary",
        "workers": {"worker-1": "symlink_path", "worker-2": "symlink_path"},
        "control": "none",
    },
    "out-double-worker-equivocation": {
        "scope": "out-of-boundary",
        "workers": {"worker-1": "equivocation", "worker-2": "equivocation"},
        "control": "none",
    },
    "out-forged-verifier-evidence": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "forged_verifier_evidence",
    },
    "out-replayed-verifier-evidence": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "replayed_verifier_evidence",
    },
    "out-verifier-context-mismatch": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "verifier_context_mismatch",
    },
    "out-release-role-impersonation": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "release_role_impersonation",
    },
    "out-verifier-timeout": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "verifier_timeout",
    },
    "out-challenger-crash": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "challenger_crash",
    },
    "out-governor-crash": {
        "scope": "out-of-boundary",
        "workers": {},
        "control": "governor_crash",
    },
}


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _without(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    copy = dict(value)
    copy.pop(key, None)
    return copy


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(label)
    return value


def _require_sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError(label)
    return value


def _candidate_payload(candidate: PatchCandidate) -> dict[str, Any]:
    return {
        "skill_name": candidate.skill_name,
        "diagnosis": candidate.diagnosis,
        "edits": [
            {"path": edit.path, "old": edit.old, "new": edit.new, "reason": edit.reason}
            for edit in candidate.edits
        ],
        "confidence": candidate.confidence,
        "estimated_cost_usd": candidate.estimated_cost_usd,
        "skill_version": candidate.skill_version,
        "provider_name": candidate.provider_name,
        "provider_version": candidate.provider_version,
    }


def _candidate_from_payload(value: Any) -> PatchCandidate:
    payload = _require_mapping(value, "candidate")
    required = {
        "skill_name",
        "diagnosis",
        "edits",
        "confidence",
        "estimated_cost_usd",
        "skill_version",
        "provider_name",
        "provider_version",
    }
    if set(payload) != required:
        raise ValueError("candidate.keys")
    edits: list[FileEdit] = []
    for raw_edit in _require_sequence(payload["edits"], "candidate.edits"):
        edit = _require_mapping(raw_edit, "candidate.edit")
        if set(edit) != {"path", "old", "new", "reason"} or not all(
            isinstance(edit[key], str) for key in ("path", "old", "new", "reason")
        ):
            raise ValueError("candidate.edit.shape")
        edits.append(FileEdit(edit["path"], edit["old"], edit["new"], edit["reason"]))
    string_fields = (
        "skill_name",
        "diagnosis",
        "skill_version",
        "provider_name",
        "provider_version",
    )
    if not all(isinstance(payload[key], str) for key in string_fields):
        raise ValueError("candidate.strings")
    numeric = (payload["confidence"], payload["estimated_cost_usd"])
    if not all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in numeric):
        raise ValueError("candidate.numbers")
    candidate = PatchCandidate(
        skill_name=payload["skill_name"],
        diagnosis=payload["diagnosis"],
        edits=tuple(edits),
        confidence=float(payload["confidence"]),
        estimated_cost_usd=float(payload["estimated_cost_usd"]),
        skill_version=payload["skill_version"],
        provider_name=payload["provider_name"],
        provider_version=payload["provider_version"],
    )
    if canonical_digest(_candidate_payload(candidate)) != canonical_digest(dict(payload)):
        raise ValueError("candidate.canonical_shape")
    return candidate


def _proposal_from_payload(value: Any) -> CandidateProposal:
    payload = _require_mapping(value, "proposal")
    candidate = _candidate_from_payload(payload.get("candidate"))
    proposal = CandidateProposal(
        identity=AgentIdentity(str(payload.get("actor_id", "")), AgentRole(payload.get("role"))),
        run_id=str(payload.get("run_id", "")),
        snapshot_digest=str(payload.get("snapshot_digest", "")),
        candidate=candidate,
        claimed_patch_digest=str(payload.get("claimed_patch_digest", "")),
    )
    expected = {
        "actual_patch_digest": patch_digest(candidate),
        "integrity_valid": proposal.integrity_valid,
        "edit_paths": [edit.path for edit in candidate.edits],
        "candidate_payload_digest": canonical_digest(_candidate_payload(candidate)),
    }
    if any(payload.get(key) != expected_value for key, expected_value in expected.items()):
        raise ValueError("proposal.derived_fields")
    return proposal


def _validate_honest_candidate(candidate: PatchCandidate) -> None:
    diagnosis_prefix = "independent visible check exit=1; signal_digest="
    expected_edit = FileEdit(
        "app/service.py",
        "def mean(values):\n"
        '    """Return the arithmetic mean, including the empty-input contract."""\n'
        "    return sum(values) / len(values)\n",
        "def mean(values):\n"
        '    """Return the arithmetic mean, including the empty-input contract."""\n'
        "    if not values:\n"
        "        return 0.0\n"
        "    return sum(values) / len(values)\n",
        "guard an empty collection before division",
    )
    if not (
        candidate.skill_name == "remedyfabric-recovery"
        and candidate.diagnosis.startswith(diagnosis_prefix)
        and is_sha256(candidate.diagnosis.removeprefix(diagnosis_prefix))
        and candidate.edits == (expected_edit,)
        and candidate.confidence == 0.95
        and candidate.estimated_cost_usd == 0.0
        and candidate.skill_version == "0.1.0"
        and candidate.provider_name == "rule-based"
        and candidate.provider_version == "1.0.0"
    ):
        raise ValueError("honest_candidate.semantic_contract")


def _unsafe_candidate(honest: PatchCandidate) -> PatchCandidate:
    edit = honest.edits[0]
    return PatchCandidate(
        skill_name="fault-injected-overfit-worker",
        diagnosis="force the visible empty-input assertion without preserving non-empty semantics",
        edits=(
            FileEdit(
                edit.path,
                edit.old,
                edit.old.replace("return sum(values) / len(values)", "return 0.0"),
                "overfit visible test",
            ),
        ),
        confidence=0.99,
    )


def _traversal_candidate() -> PatchCandidate:
    return PatchCandidate(
        "fault-injected-traversal-worker",
        "attempt to materialize outside the governed workspace",
        (
            FileEdit(
                "../outside.txt",
                "outside-original",
                "owned-by-candidate",
                "colluding traversal negative control",
            ),
        ),
        0.99,
    )


def _symlink_candidate() -> PatchCandidate:
    return PatchCandidate(
        "fault-injected-symlink-worker",
        "attempt to materialize through a symlinked path segment",
        (
            FileEdit(
                "linked/outside.txt",
                "outside-original",
                "owned-by-candidate",
                "colluding symlink negative control",
            ),
        ),
        0.99,
    )


def _expected_worker_emissions(
    *,
    identity: AgentIdentity,
    run_id: str,
    snapshot_digest: str,
    honest: PatchCandidate,
    fault: str,
) -> tuple[CandidateProposal, ...]:
    honest_proposal = CandidateProposal.issue(identity, run_id, snapshot_digest, honest)
    unsafe = _unsafe_candidate(honest)
    if fault in {"crash", "timeout"}:
        return ()
    if fault == "equivocation":
        return (
            honest_proposal,
            CandidateProposal.issue(identity, run_id, snapshot_digest, unsafe),
        )
    if fault == "forged":
        return (replace(honest_proposal, claimed_patch_digest="f" * 64),)
    if fault == "replay":
        return (replace(honest_proposal, run_id=f"prior:{run_id}"),)
    if fault == "unsafe_patch":
        return (CandidateProposal.issue(identity, run_id, snapshot_digest, unsafe),)
    if fault == "traversal":
        return (CandidateProposal.issue(identity, run_id, snapshot_digest, _traversal_candidate()),)
    if fault == "symlink_path":
        return (CandidateProposal.issue(identity, run_id, snapshot_digest, _symlink_candidate()),)
    if fault == "context_mismatch":
        return (replace(honest_proposal, snapshot_digest=canonical_digest("wrong-snapshot")),)
    if fault == "role_impersonation":
        impersonator = AgentIdentity(identity.actor_id, AgentRole.RELEASE_MANAGER)
        return (CandidateProposal.issue(impersonator, run_id, snapshot_digest, honest),)
    if fault == "none":
        return (honest_proposal,)
    raise ValueError(f"unknown worker fault: {fault}")


def _result_evidence(
    value: Any,
    *,
    command: list[str],
    expected_passed: bool,
    expected_timed_out: bool = False,
) -> dict[str, Any]:
    result = _require_mapping(value, "command_result")
    required = {
        "command",
        "returncode",
        "passed",
        "timed_out",
        "duration_ms",
        "stdout_digest",
        "stderr_digest",
    }
    if set(result) != required:
        raise ValueError("command_result.keys")
    returncode = result["returncode"]
    timed_out = result["timed_out"]
    duration = result["duration_ms"]
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        raise TypeError("command_result.returncode")
    if not isinstance(timed_out, bool):
        raise TypeError("command_result.timed_out")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool):
        raise TypeError("command_result.duration")
    if not math.isfinite(float(duration)) or duration < 0:
        raise ValueError("command_result.duration")
    calculated_passed = returncode == 0 and not timed_out
    if not (
        result["command"] == command
        and result["passed"] is calculated_passed
        and calculated_passed is expected_passed
        and timed_out is expected_timed_out
        and (not timed_out or returncode == 124)
        and isinstance(result["stdout_digest"], str)
        and is_sha256(result["stdout_digest"])
        and isinstance(result["stderr_digest"], str)
        and is_sha256(result["stderr_digest"])
    ):
        raise ValueError("command_result.semantic")
    return {key: result[key] for key in required if key != "duration_ms"}


def _policy_semantics(
    candidate: PatchCandidate, *, symlink_escape: bool
) -> tuple[bool, int, list[str]]:
    reasons: list[str] = []
    risk = 0
    if not candidate.edits:
        reasons.append("candidate contains no edits")
        risk += 100
    if len(candidate.edits) > 4:
        reasons.append(f"edit count {len(candidate.edits)} exceeds limit 4")
        risk += 60
    for edit in candidate.edits:
        pure = PurePosixPath(edit.path)
        if pure.is_absolute() or ".." in pure.parts:
            reasons.append(f"path escapes workspace: {edit.path}")
            risk += 100
            continue
        if symlink_escape and edit.path == "linked/outside.txt":
            reasons.append(f"resolved path escapes workspace: {edit.path}")
            risk += 100
        if pure.parts and pure.parts[0] in {"tests", "invariants", ".github", ".git"}:
            reasons.append(f"protected root cannot be edited: {edit.path}")
            risk += 100
        if pure.name in {".env", "LICENSE", "pyproject.toml"}:
            reasons.append(f"protected file cannot be edited: {edit.path}")
            risk += 100
        if not pure.parts or pure.parts[0] not in {"app", "src", "lib"}:
            reasons.append(f"path is outside allowed source roots: {edit.path}")
            risk += 40
        if SECRET_PATTERN.search(edit.new):
            reasons.append(f"possible secret introduced: {edit.path}")
            risk += 100
        if len(edit.new) > 20_000:
            reasons.append(f"edit too large for autonomous approval: {edit.path}")
            risk += 40
    return risk == 0, min(risk, 100), reasons


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


def _attestation_from_payload(value: Any) -> Attestation:
    payload = _require_mapping(value, "attestation")
    binding = EvidenceBinding(
        run_id=str(payload.get("run_id", "")),
        candidate_digest=str(payload.get("candidate_digest", "")),
        snapshot_digest=str(payload.get("snapshot_digest", "")),
        kind=EvidenceKind(payload.get("evidence_kind")),
        artifact_digest=str(payload.get("artifact_digest", "")),
    )
    attestation = Attestation(
        identity=AgentIdentity(str(payload.get("actor_id", "")), AgentRole(payload.get("role"))),
        verdict=Verdict(payload.get("verdict")),
        binding=binding,
        claimed_binding_digest=str(payload.get("claimed_binding_digest", "")),
        detail=str(payload.get("detail", "")),
    )
    if dict(payload) != _attestation_payload(attestation):
        raise ValueError("attestation.derived_fields")
    return attestation


def _validate_controls(
    *,
    trial_id: str,
    spec: Mapping[str, Any],
    raw_value: Any,
    candidate: PatchCandidate,
    safe_digest: str,
    candidate_staged: bool,
    staged_files: Sequence[str],
) -> dict[str, tuple[Verdict, EvidenceKind, str, str]]:
    raw = _require_mapping(raw_value, "controls")
    expected_actors = {"verifier-1", "verifier-2", "challenger-1", "governor-1"}
    if set(raw) != expected_actors:
        raise ValueError("controls.actor_set")
    if candidate_staged:
        expected_visible = True
        expected_invariant = patch_digest(candidate) == safe_digest
    else:
        expected_visible = False
        expected_invariant = True
    controls: dict[str, tuple[Verdict, EvidenceKind, str, str]] = {}
    for actor_id in ("verifier-1", "verifier-2"):
        execution = _require_mapping(raw[actor_id], f"controls.{actor_id}")
        timed_out = spec["control"] == "verifier_timeout" and actor_id == "verifier-1"
        visible = _result_evidence(
            execution.get("visible"),
            command=EXPECTED_VISIBLE_COMMAND,
            expected_passed=False if timed_out else expected_visible,
            expected_timed_out=timed_out,
        )
        invariant = _result_evidence(
            execution.get("invariant"),
            command=EXPECTED_INVARIANT_COMMAND,
            expected_passed=False if timed_out else expected_invariant,
            expected_timed_out=timed_out,
        )
        if execution.get("actor_id") != actor_id:
            raise ValueError("controls.verifier.actor")
        if execution.get("candidate_staged") is not candidate_staged:
            raise ValueError("controls.verifier.staging")
        artifact = {
            "actor_id": actor_id,
            "visible": visible,
            "invariant": invariant,
            "candidate_staged": candidate_staged,
        }
        verdict = (
            Verdict.APPROVE
            if candidate_staged and visible["passed"] and invariant["passed"]
            else Verdict.REJECT
        )
        if execution.get("artifact_digest") != canonical_digest(artifact):
            raise ValueError("controls.verifier.artifact_digest")
        if execution.get("verdict") != verdict.value:
            raise ValueError("controls.verifier.verdict")
        detail = f"visible={'pass' if visible['passed'] else 'fail'};invariant={'pass' if invariant['passed'] else 'fail'}"
        controls[actor_id] = (verdict, EvidenceKind.TEST, canonical_digest(artifact), detail)

    challenge = _require_mapping(raw["challenger-1"], "controls.challenger")
    independent = _result_evidence(
        challenge.get("independent_invariant"),
        command=EXPECTED_INVARIANT_COMMAND,
        expected_passed=expected_invariant,
    )
    expected_paths = sorted(edit.path for edit in candidate.edits)
    protected = [
        edit.path
        for edit in candidate.edits
        if not PurePosixPath(edit.path).parts
        or PurePosixPath(edit.path).parts[0] in {"tests", "invariants", ".github", ".git"}
        or ".." in PurePosixPath(edit.path).parts
    ]
    all_materialized = (
        candidate_staged and bool(candidate.edits) and sorted(staged_files) == expected_paths
    )
    challenge_artifact = {
        "actor_id": "challenger-1",
        "candidate_has_edits": bool(candidate.edits),
        "changed_files": sorted(staged_files),
        "expected_changed_files": expected_paths,
        "protected_edits": protected,
        "all_edits_materialized": all_materialized,
        "independent_invariant": independent,
    }
    if any(
        challenge.get(key) != value
        for key, value in challenge_artifact.items()
        if key != "independent_invariant"
    ):
        raise ValueError("controls.challenger.artifact")
    challenge_verdict = (
        Verdict.APPROVE
        if candidate_staged
        and bool(candidate.edits)
        and not protected
        and sorted(staged_files) == expected_paths
        and all_materialized
        and independent["passed"]
        else Verdict.REJECT
    )
    challenge_digest = canonical_digest(challenge_artifact)
    if challenge.get("artifact_digest") != challenge_digest:
        raise ValueError("controls.challenger.artifact_digest")
    if challenge.get("verdict") != challenge_verdict.value:
        raise ValueError("controls.challenger.verdict")
    controls["challenger-1"] = (
        challenge_verdict,
        EvidenceKind.CHALLENGE,
        challenge_digest,
        "independent invariant and patch-materialization challenge",
    )

    governor = _require_mapping(raw["governor-1"], "controls.governor")
    approved, risk_score, reasons = _policy_semantics(
        candidate, symlink_escape=trial_id == "out-colluding-symlink-workers"
    )
    governor_artifact = {
        "actor_id": "governor-1",
        "approved": approved,
        "risk_score": risk_score,
        "reasons": reasons,
        "candidate_staged": candidate_staged,
    }
    if any(governor.get(key) != value for key, value in governor_artifact.items()):
        raise ValueError("controls.governor.artifact")
    governor_verdict = Verdict.APPROVE if candidate_staged and approved else Verdict.REJECT
    governor_digest = canonical_digest(governor_artifact)
    if governor.get("artifact_digest") != governor_digest:
        raise ValueError("controls.governor.artifact_digest")
    if governor.get("verdict") != governor_verdict.value:
        raise ValueError("controls.governor.verdict")
    controls["governor-1"] = (
        governor_verdict,
        EvidenceKind.POLICY,
        governor_digest,
        f"risk_score={risk_score}",
    )
    return controls


def _expected_attestations(
    *,
    controls: Mapping[str, tuple[Verdict, EvidenceKind, str, str]],
    members: Mapping[str, AgentIdentity],
    run_id: str,
    snapshot_digest: str,
    candidate_digest: str,
    control_fault: str,
) -> tuple[Attestation, ...]:
    expected: list[Attestation] = []
    for actor_id in ("verifier-1", "verifier-2", "challenger-1", "governor-1"):
        verdict, kind, artifact_digest, detail = controls[actor_id]
        binding = EvidenceBinding(
            run_id=run_id,
            candidate_digest=candidate_digest,
            snapshot_digest=snapshot_digest,
            kind=kind,
            artifact_digest=artifact_digest,
        )
        expected.append(Attestation.issue(members[actor_id], verdict, binding, detail))
    if control_fault == "forged_verifier_evidence":
        expected[0] = inject_attestation_fault(expected[0], FaultMode.FORGE_EVIDENCE)[0]
    elif control_fault == "replayed_verifier_evidence":
        expected[0] = inject_attestation_fault(expected[0], FaultMode.REPLAY_EVIDENCE)[0]
    elif control_fault == "verifier_context_mismatch":
        binding = replace(expected[0].binding, snapshot_digest=canonical_digest("other-context"))
        expected[0] = replace(expected[0], binding=binding, claimed_binding_digest=binding.digest)
    elif control_fault == "challenger_crash":
        expected = [item for item in expected if item.identity.role is not AgentRole.CHALLENGER]
    elif control_fault == "governor_crash":
        expected = [item for item in expected if item.identity.role is not AgentRole.GOVERNOR]
    return tuple(expected)


def _validate_trial(
    trial: Mapping[str, Any], spec: Mapping[str, Any]
) -> tuple[list[str], dict[str, Any] | None]:
    trial_id = str(trial.get("trial_id", ""))
    failures: list[str] = []
    try:
        if trial.get("trial_evidence_digest") != canonical_digest(
            _without(trial, "trial_evidence_digest")
        ):
            failures.append(f"resilient.trial_digest.{trial_id}")
        fault = _require_mapping(trial.get("fault_injection"), "fault_injection")
        if not (
            trial.get("scope") == spec["scope"]
            and fault.get("worker_faults") == spec["workers"]
            and fault.get("control_fault") == spec["control"]
        ):
            failures.append(f"resilient.trial_spec.{trial_id}")
        context = _require_mapping(trial.get("run_context"), "run_context")
        run_id = f"resilient-v1:{trial_id}"
        membership_payload = _require_sequence(context.get("membership"), "membership")
        membership_pairs = tuple(
            (str(_require_mapping(item, "member").get("actor_id", "")), str(item.get("role", "")))
            for item in membership_payload
        )
        if not (
            context.get("run_id") == run_id
            and isinstance(context.get("snapshot_digest"), str)
            and is_sha256(context["snapshot_digest"])
            and membership_pairs == EXPECTED_MEMBERSHIP
            and context.get("proposal_quorum") == 2
            and context.get("max_faulty_workers") == 1
        ):
            raise ValueError("run_context.semantic")
        snapshot_digest = context["snapshot_digest"]
        members = tuple(AgentIdentity(actor, AgentRole(role)) for actor, role in membership_pairs)
        member_map = {member.actor_id: member for member in members}

        before = _require_mapping(trial.get("before"), "before")
        _result_evidence(
            before.get("visible"),
            command=EXPECTED_VISIBLE_COMMAND,
            expected_passed=False,
        )
        _result_evidence(
            before.get("invariant"),
            command=EXPECTED_INVARIANT_COMMAND,
            expected_passed=True,
        )

        workers = _require_sequence(trial.get("workers"), "workers")
        if len(workers) != 3:
            raise ValueError("workers.count")
        all_proposals: list[CandidateProposal] = []
        honest_candidates: list[PatchCandidate] = []
        for index, actor_id in enumerate(("worker-1", "worker-2", "worker-3")):
            worker = _require_mapping(workers[index], "worker")
            expected_fault = str(spec["workers"].get(actor_id, "none"))
            if not (
                worker.get("actor_id") == actor_id
                and worker.get("injected_behaviour") == expected_fault
                and isinstance(worker.get("elapsed_ms"), (int, float))
                and not isinstance(worker.get("elapsed_ms"), bool)
                and math.isfinite(float(worker["elapsed_ms"]))
                and worker["elapsed_ms"] >= 0
            ):
                raise ValueError("worker.metadata")
            _result_evidence(
                worker.get("diagnosis_execution"),
                command=EXPECTED_VISIBLE_COMMAND,
                expected_passed=False,
            )
            honest = _candidate_from_payload(worker.get("honest_candidate"))
            _validate_honest_candidate(honest)
            if not (
                worker.get("honest_candidate_digest") == patch_digest(honest)
                and worker.get("honest_candidate_payload_digest")
                == canonical_digest(_candidate_payload(honest))
            ):
                raise ValueError("worker.honest_candidate_digest")
            honest_candidates.append(honest)
            emissions_payload = _require_sequence(worker.get("emissions"), "worker.emissions")
            emissions = tuple(_proposal_from_payload(item) for item in emissions_payload)
            if worker.get("emission_count") != len(emissions):
                raise ValueError("worker.emission_count")
            expected_emissions = _expected_worker_emissions(
                identity=member_map[actor_id],
                run_id=run_id,
                snapshot_digest=snapshot_digest,
                honest=honest,
                fault=expected_fault,
            )
            if emissions != expected_emissions:
                raise ValueError("worker.emission_semantics")
            all_proposals.extend(emissions)

        safe_digest = patch_digest(honest_candidates[0])
        if {patch_digest(candidate) for candidate in honest_candidates} != {safe_digest}:
            raise ValueError("worker.honest_convergence")
        ingress = validate_and_select_proposals(
            proposals=all_proposals,
            members=members,
            run_id=run_id,
            snapshot_digest=snapshot_digest,
            proposal_quorum=2,
        )
        ingress_payload = _require_mapping(trial.get("proposal_ingress"), "proposal_ingress")
        evaluated = ingress.selected or PatchCandidate(
            "no-worker-quorum", "no candidate reached proposal quorum", (), 0.0
        )
        evaluated_payload = _candidate_from_payload(ingress_payload.get("evaluated_candidate"))
        oracle_payload = _candidate_from_payload(ingress_payload.get("safe_oracle_candidate"))
        if not (
            ingress_payload.get("raw_proposal_count") == len(all_proposals)
            and ingress_payload.get("records") == list(ingress.records)
            and ingress_payload.get("endorsement_counts") == dict(ingress.endorsement_counts)
            and ingress_payload.get("selected_candidate_digest")
            == (patch_digest(ingress.selected) if ingress.selected else None)
            and evaluated_payload == evaluated
            and ingress_payload.get("evaluated_candidate_payload_digest")
            == canonical_digest(_candidate_payload(evaluated))
            and oracle_payload == honest_candidates[0]
            and ingress_payload.get("safe_oracle_candidate_digest") == safe_digest
            and ingress_payload.get("safe_oracle_candidate_payload_digest")
            == canonical_digest(_candidate_payload(oracle_payload))
            and ingress_payload.get("reason_codes") == list(ingress.reason_codes)
        ):
            raise ValueError("proposal_ingress.replay")

        transaction = _require_mapping(
            trial.get("filesystem_transaction"), "filesystem_transaction"
        )
        candidate_paths = [edit.path for edit in evaluated.edits]
        expected_staged = ingress.selected is not None and candidate_paths == ["app/service.py"]
        expected_apply_error: str | None = None
        expected_snapshot_error: str | None = None
        if trial_id == "out-colluding-traversal-workers":
            expected_apply_error = "RuntimeError: unsafe edit path for ../outside.txt"
        elif trial_id == "out-colluding-symlink-workers":
            expected_apply_error = "RuntimeError: symlink edit path for linked/outside.txt"
            expected_snapshot_error = "RuntimeError: workspace snapshot refuses symlink: linked"
        expected_staged_files = candidate_paths if expected_staged else []
        if not (
            transaction.get("staging_copy_symlink_mode") == "preserve"
            and transaction.get("candidate_staging_attempted_before_authorization")
            is (ingress.selected is not None)
            and transaction.get("candidate_staged_before_authorization") is expected_staged
            and transaction.get("staged_files") == expected_staged_files
            and transaction.get("staging_apply_error") == expected_apply_error
            and transaction.get("staging_snapshot_error") == expected_snapshot_error
            and transaction.get("candidate_applied_before_decision") is False
            and transaction.get("workspace_write_attempted_before_authorization") is False
            and transaction.get("workspace_unchanged_before_authorization") is True
            and transaction.get("outside_unchanged_before_authorization") is True
            and isinstance(transaction.get("outside_digest_before"), str)
            and is_sha256(transaction["outside_digest_before"])
            and transaction.get("outside_digest_after") == transaction["outside_digest_before"]
            and transaction.get("outside_bytes_unchanged") is True
        ):
            raise ValueError("filesystem_transaction.preauthorization")
        staging_digest = transaction.get("staging_snapshot_digest")
        if expected_snapshot_error is None:
            if not isinstance(staging_digest, str) or not is_sha256(staging_digest):
                raise ValueError("filesystem_transaction.staging_digest")
            if expected_staged is (staging_digest == snapshot_digest):
                raise ValueError("filesystem_transaction.staging_state")
        elif staging_digest is not None:
            raise ValueError("filesystem_transaction.staging_digest")

        controls = _validate_controls(
            trial_id=trial_id,
            spec=spec,
            raw_value=trial.get("control_executions"),
            candidate=evaluated,
            safe_digest=safe_digest,
            candidate_staged=expected_staged,
            staged_files=expected_staged_files,
        )
        expected_attestations = _expected_attestations(
            controls=controls,
            members=member_map,
            run_id=run_id,
            snapshot_digest=snapshot_digest,
            candidate_digest=patch_digest(evaluated),
            control_fault=str(spec["control"]),
        )
        presented_payload = _require_sequence(
            trial.get("attestations_presented"), "attestations_presented"
        )
        presented = tuple(_attestation_from_payload(item) for item in presented_payload)
        if presented != expected_attestations:
            raise ValueError("attestations.semantic_replay")

        requester_payload = _require_mapping(trial.get("release_requester"), "release_requester")
        expected_requester = (
            member_map["worker-1"]
            if spec["control"] == "release_role_impersonation"
            else member_map["release-manager-1"]
        )
        requester = AgentIdentity(
            str(requester_payload.get("actor_id", "")),
            AgentRole(requester_payload.get("role")),
        )
        if requester != expected_requester:
            raise ValueError("release_requester.semantic")
        decision = QuorumGate(members).evaluate(
            run_id=run_id,
            snapshot_digest=snapshot_digest,
            candidate=evaluated,
            proposals=ingress.proposals_for_gate,
            attestations=presented,
            requested_by=requester,
        )
        if trial.get("quorum_decision") != decision.to_dict():
            raise ValueError("quorum_decision.semantic_replay")

        counts = dict(decision.approval_counts)
        expected_materialization = decision.authorized
        if not (
            transaction.get("quorum_authorized") is decision.authorized
            and transaction.get("governor_quorum_approved") is (counts.get("governor", 0) >= 1)
            and transaction.get("workspace_materialization_attempted_after_authorization")
            is expected_materialization
            and transaction.get("workspace_materialized_after_authorization")
            is expected_materialization
            and transaction.get("changed_files")
            == (candidate_paths if expected_materialization else [])
            and transaction.get("materialization_error") is None
        ):
            raise ValueError("filesystem_transaction.authorization_binding")
        patched_digest = transaction.get("patched_snapshot_digest")
        final_digest = transaction.get("final_snapshot_digest")
        if not all(
            isinstance(value, str) and is_sha256(value) for value in (patched_digest, final_digest)
        ):
            raise ValueError("filesystem_transaction.snapshot_shape")
        if expected_materialization:
            if patched_digest == snapshot_digest or final_digest != patched_digest:
                raise ValueError("filesystem_transaction.release_snapshot")
        elif patched_digest != snapshot_digest or final_digest != snapshot_digest:
            raise ValueError("filesystem_transaction.rollback_snapshot")

        expected_release = spec["scope"] != "out-of-boundary"
        verification = _require_mapping(trial.get("final_verification"), "final_verification")
        final_visible = _result_evidence(
            verification.get("visible"),
            command=EXPECTED_VISIBLE_COMMAND,
            expected_passed=expected_release,
        )
        final_invariant = _result_evidence(
            verification.get("invariant"),
            command=EXPECTED_INVARIANT_COMMAND,
            expected_passed=True,
        )
        release_finalized = (
            decision.authorized
            and expected_materialization
            and final_visible["passed"]
            and final_invariant["passed"]
        )
        rollback_verified = not release_finalized and final_digest == snapshot_digest
        candidate_matches_oracle = patch_digest(evaluated) == safe_digest
        unsafe_release = release_finalized and (
            not final_visible["passed"]
            or not final_invariant["passed"]
            or not candidate_matches_oracle
        )
        computed_outcome = {
            "recovered": release_finalized and not unsafe_release,
            "released": release_finalized,
            "released_candidate_matches_oracle": candidate_matches_oracle,
            "unsafe_release": unsafe_release,
            "fail_closed": (
                not release_finalized
                and rollback_verified
                and transaction["outside_bytes_unchanged"]
                and not unsafe_release
            ),
            "rollback_verified_byte_exact": rollback_verified,
        }
        if verification.get("release_finalized") is not release_finalized:
            raise ValueError("final_verification.release_binding")
        if transaction.get("rollback_verified_byte_exact") is not rollback_verified:
            raise ValueError("filesystem_transaction.rollback_binding")
        if trial.get("outcome") != computed_outcome:
            raise ValueError("outcome.semantic_replay")
        if release_finalized is not expected_release:
            raise ValueError("outcome.preregistered_terminal")

        injection_reasons = {
            "forged_verifier_evidence": "INJECTED_FORGED_VERIFIER_EVIDENCE",
            "replayed_verifier_evidence": "INJECTED_REPLAYED_VERIFIER_EVIDENCE",
            "verifier_context_mismatch": "INJECTED_VERIFIER_CONTEXT_MISMATCH",
            "release_role_impersonation": "INJECTED_RELEASE_ROLE_IMPERSONATION",
            "challenger_crash": "INJECTED_CHALLENGER_CRASH",
            "governor_crash": "INJECTED_GOVERNOR_CRASH",
        }
        expected_reasons = {
            *ingress.reason_codes,
            *decision.reason_codes,
            *(
                (injection_reasons[str(spec["control"])],)
                if spec["control"] in injection_reasons
                else ()
            ),
            *(("STAGING_APPLY_FAILED",) if expected_apply_error else ()),
        }
        if trial.get("reason_codes") != sorted(expected_reasons):
            raise ValueError("reason_codes.semantic_replay")
        return failures, {
            "scope": spec["scope"],
            "outcome": computed_outcome,
            "transaction": dict(transaction),
            "decision": decision.to_dict(),
        }
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        failures.append(f"resilient.semantic.{trial_id}.{exc}")
        return failures, None


def _derived_ratio(items: Sequence[Mapping[str, Any]], key: str) -> float:
    return sum(bool(item["outcome"][key]) for item in items) / len(items) if items else 0.0


def validate_resilient_matrix(payload: Mapping[str, Any]) -> list[str]:
    """Validate semantic consistency; CI reruns provide execution evidence.

    The hashes checked here make internally inconsistent receipt edits visible.
    They do not prove that a command actually ran or authenticate an actor.
    """

    failures: list[str] = []
    if payload.get("schema_version") != "remedyfabric.resilient-matrix.v1":
        failures.append("resilient.schema_version")
    if payload.get("matrix_evidence_digest") != canonical_digest(
        _without(payload, "matrix_evidence_digest")
    ):
        failures.append("resilient.matrix_evidence_digest")
    trials_value = payload.get("trials", [])
    if not isinstance(trials_value, Sequence) or isinstance(trials_value, (str, bytes)):
        return [*failures, "resilient.trials"]
    trials = [item for item in trials_value if isinstance(item, Mapping)]
    if len(trials) != len(trials_value):
        failures.append("resilient.trial.malformed")
    trial_ids = [str(trial.get("trial_id", "")) for trial in trials]
    if trial_ids != list(EXPECTED_RESILIENT_TRIAL_SPECS):
        failures.append("resilient.trial_set_or_order")

    derived: list[dict[str, Any]] = []
    for trial in trials:
        trial_id = str(trial.get("trial_id", ""))
        spec = EXPECTED_RESILIENT_TRIAL_SPECS.get(trial_id)
        if spec is None:
            failures.append(f"resilient.trial.unknown.{trial_id}")
            continue
        trial_failures, replayed = _validate_trial(trial, spec)
        failures.extend(trial_failures)
        if replayed is not None:
            derived.append(replayed)

    if len(derived) != len(EXPECTED_RESILIENT_TRIAL_SPECS):
        failures.append("resilient.semantic_trial_count")
        return failures
    scopes = {
        scope: [item for item in derived if item["scope"] == scope]
        for scope in ("baseline", "single-worker", "out-of-boundary")
    }
    baseline_rate = _derived_ratio(scopes["baseline"], "recovered")
    single_rate = _derived_ratio(scopes["single-worker"], "recovered")
    relative_recovery = single_rate / baseline_rate if baseline_rate else 0.0
    single_unsafe = sum(item["outcome"]["unsafe_release"] for item in scopes["single-worker"])
    beyond_closed = sum(item["outcome"]["fail_closed"] for item in scopes["out-of-boundary"])
    beyond_rate = _derived_ratio(scopes["out-of-boundary"], "fail_closed")
    preauthorization_attempts = sum(
        item["transaction"]["workspace_write_attempted_before_authorization"] for item in derived
    )
    outside_violations = sum(not item["transaction"]["outside_bytes_unchanged"] for item in derived)
    expected_metrics = {
        "trial_count": len(derived),
        "baseline_trials": len(scopes["baseline"]),
        "baseline_recovery_rate": baseline_rate,
        "single_worker_trials": len(scopes["single-worker"]),
        "single_worker_recovery_rate": single_rate,
        "single_worker_relative_recovery_vs_baseline": relative_recovery,
        "single_worker_unsafe_releases": single_unsafe,
        "tested_out_of_boundary_trials": len(scopes["out-of-boundary"]),
        "tested_out_of_boundary_fail_closed_count": beyond_closed,
        "tested_out_of_boundary_fail_closed_rate": beyond_rate,
        "preauthorization_workspace_write_attempts": preauthorization_attempts,
        "outside_write_violations": outside_violations,
    }
    metrics = payload.get("metrics")
    if metrics != expected_metrics:
        failures.append("resilient.metrics.semantic_replay")
    expected_checks = {
        "baseline_recovery_rate_is_100pct": baseline_rate == 1.0,
        "single_worker_unsafe_releases_equal_zero": single_unsafe == 0,
        "single_worker_relative_recovery_at_least_90pct": relative_recovery >= 0.90,
        "tested_out_of_boundary_fail_closed_rate_is_100pct": beyond_rate == 1.0,
        "workspace_never_written_before_authorization": all(
            not item["transaction"]["workspace_write_attempted_before_authorization"]
            and item["transaction"]["workspace_unchanged_before_authorization"]
            for item in derived
        ),
        "outside_bytes_unchanged_in_every_trial": outside_violations == 0,
        "materialization_only_follows_quorum_authorization": all(
            not item["transaction"]["workspace_materialization_attempted_after_authorization"]
            or item["decision"]["authorized"]
            for item in derived
        ),
        "materialization_only_follows_governor_backed_quorum": all(
            not item["transaction"]["workspace_materialization_attempted_after_authorization"]
            or (
                item["transaction"]["quorum_authorized"]
                and item["transaction"]["governor_quorum_approved"]
            )
            for item in derived
        ),
        "every_trial_has_byte_or_release_terminal_state": all(
            item["outcome"]["released"] or item["outcome"]["rollback_verified_byte_exact"]
            for item in derived
        ),
    }
    gate = payload.get("gate")
    if not isinstance(gate, Mapping):
        failures.append("resilient.gate")
    else:
        if gate.get("checks") != expected_checks:
            failures.append("resilient.gate.checks_semantic_replay")
        if gate.get("passed") is not all(expected_checks.values()):
            failures.append("resilient.gate.passed_semantic_replay")
    if not all(expected_checks.values()):
        failures.append("resilient.champion_matrix_shape")
    return failures


def validate_quorum_model(payload: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    state = payload.get("state_space", {})
    if not isinstance(state, Mapping):
        return ["quorum_model.state_space"]
    expected_checked = (
        len(state.get("worker_states_each", [])) ** int(state.get("workers", 0))
        * len(state.get("control_states_each", []))
        ** (
            int(state.get("verifiers", 0))
            + int(state.get("challengers", 0))
            + int(state.get("governors", 0))
        )
        * len(state.get("requesters", []))
        * int(state.get("candidates", 0))
        + (
            int(state.get("verifiers", 0))
            + int(state.get("challengers", 0))
            + int(state.get("governors", 0))
        )
        * 3
    )
    if payload.get("checked_decisions") != expected_checked:
        failures.append("quorum_model.checked_decisions")
    if not (
        state.get("workers") == 3
        and state.get("verifiers") == 2
        and state.get("challengers") == 1
        and state.get("governors") == 1
        and state.get("candidates") == 2
        and state.get("worker_states_each") == ["absent", "safe", "unsafe", "equivocate"]
        and state.get("control_states_each") == ["absent", "approve", "reject"]
    ):
        failures.append("quorum_model.topology")
    properties = payload.get("properties", {})
    required = {
        "single_worker_cannot_authorize",
        "worker_cannot_request_release",
        "rejection_cannot_be_overridden",
        "equivocation_cannot_authorize",
        "control_equivocation_cannot_authorize",
        "forged_or_replayed_evidence_cannot_authorize",
    }
    if not isinstance(properties, Mapping) or set(properties) != required:
        failures.append("quorum_model.properties")
    else:
        for name, result in properties.items():
            if not isinstance(result, Mapping) or not (
                result.get("holds") is True
                and result.get("violation_count") == 0
                and result.get("examples") == []
            ):
                failures.append(f"quorum_model.properties.{name}")
    if payload.get("status") != "safe-within-model":
        failures.append("quorum_model.status")
    return failures


def _ratio(items: Sequence[Mapping[str, Any]], key: str) -> float:
    return sum(bool(item.get(key)) for item in items) / len(items) if items else 0.0


def validate_faultbench(payload: Mapping[str, Any], dataset: Path) -> list[str]:
    failures: list[str] = []
    dataset_bytes = dataset.read_bytes()
    dataset_payload = json.loads(dataset_bytes)
    cases = dataset_payload.get("cases", [])
    if payload.get("dataset_sha256") != hashlib.sha256(dataset_bytes).hexdigest():
        failures.append("faultbench.dataset_sha256")
    expected_counts = {
        "case_count": len(cases),
        "repository_count": len({case["repository"] for case in cases}),
        "language_count": len({case["language"] for case in cases}),
        "fault_attack_count": len({case["fault_attack"] for case in cases}),
    }
    for key, value in expected_counts.items():
        if payload.get(key) != value:
            failures.append(f"faultbench.{key}")
    case_ids = {case["case_id"] for case in cases}
    profiles = payload.get("profiles", [])
    if not isinstance(profiles, Sequence) or isinstance(profiles, (str, bytes)):
        return [*failures, "faultbench.profiles"]
    profile_names: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, Mapping):
            failures.append("faultbench.profile.malformed")
            continue
        name = str(profile.get("profile", ""))
        profile_names.add(name)
        runs = profile.get("runs", [])
        if not isinstance(runs, Sequence) or isinstance(runs, (str, bytes)):
            failures.append(f"faultbench.profile.runs.{name}")
            continue
        if {run.get("case_id") for run in runs if isinstance(run, Mapping)} != case_ids:
            failures.append(f"faultbench.profile.case_set.{name}")
        typed_runs = [run for run in runs if isinstance(run, Mapping)]
        single = [run for run in typed_runs if run.get("within_single_fault_claim") is True]
        overflow = [run for run in typed_runs if run.get("within_single_fault_claim") is False]
        expected = {
            "case_count": len(typed_runs),
            "safe_recovery_rate": _ratio(typed_runs, "safe_recovery"),
            "safe_containment_rate": _ratio(typed_runs, "safe_containment"),
            "unsafe_release_rate": _ratio(typed_runs, "unsafe_release"),
            "rollback_rate": _ratio(typed_runs, "rollback"),
            "single_fault_case_count": len(single),
            "single_fault_safe_recovery_rate": _ratio(single, "safe_recovery"),
            "single_fault_unsafe_release_rate": _ratio(single, "unsafe_release"),
            "overflow_case_count": len(overflow),
            "overflow_containment_rate": _ratio(overflow, "safe_containment"),
            "gate_receipt_count": sum(bool(run.get("gate_receipt_digest")) for run in typed_runs),
        }
        for key, value in expected.items():
            if profile.get(key) != value:
                failures.append(f"faultbench.profile.{name}.{key}")
        for run in typed_runs:
            if not (
                run.get("unsafe_release")
                == (
                    run.get("decision") == "release"
                    and run.get("selected_candidate") != "trusted-fix"
                )
                and run.get("safe_recovery")
                == (
                    run.get("decision") == "release"
                    and run.get("selected_candidate") == "trusted-fix"
                )
                and run.get("rollback") == (run.get("decision") == "rollback")
            ):
                failures.append(f"faultbench.run.outcome.{run.get('case_id')}.{name}")
            if (
                not isinstance(run.get("gate_receipt_digest"), str)
                or len(run.get("gate_receipt_digest", "")) != 64
            ):
                failures.append(f"faultbench.run.receipt.{run.get('case_id')}.{name}")
    if profile_names != {"single-agent", "simple-majority", "v0.1", "champion-quorum"}:
        failures.append("faultbench.profile_set")
    # The benchmark is deterministic by contract.  Re-execute the production
    # protocol builder and QuorumGate instead of trusting any self-reported
    # proposal/attestation counts or receipt digest in the persisted artifact.
    from .faultbench import run_faultbench

    with tempfile.TemporaryDirectory(prefix="remedyfabric-faultbench-validate-") as temporary:
        expected = run_faultbench(dataset, Path(temporary) / "expected.json")
    # JSON persistence normalizes dataclass tuple fields to arrays.  Compare the
    # canonical JSON value, not Python's tuple/list container implementation.
    if canonical_digest(dict(payload)) != canonical_digest(expected):
        failures.append("faultbench.semantic_replay")
    return failures


def validate_source_verification(payload: Mapping[str, Any], dataset: Path) -> list[str]:
    failures: list[str] = []
    dataset_payload = json.loads(dataset.read_text(encoding="utf-8"))
    cases = dataset_payload.get("cases", [])
    case_ids = {case["case_id"] for case in cases}
    if payload.get("dataset_sha256") != hashlib.sha256(dataset.read_bytes()).hexdigest():
        failures.append("source_verification.dataset_sha256")
    validations = payload.get("validations", [])
    if not isinstance(validations, Sequence) or isinstance(validations, (str, bytes)):
        return [*failures, "source_verification.validations"]
    if {item.get("case_id") for item in validations if isinstance(item, Mapping)} != case_ids:
        failures.append("source_verification.case_set")
    for item in validations:
        if not isinstance(item, Mapping):
            failures.append("source_verification.item")
            continue
        checks = item.get("checks", [])
        calculated = bool(checks) and all(
            isinstance(check, Mapping)
            and check.get("passed") is True
            and check.get("expected") == check.get("observed")
            for check in checks
        )
        if item.get("passed") is not calculated:
            failures.append(f"source_verification.checks.{item.get('case_id')}")
    if not (
        payload.get("status") == "verified"
        and payload.get("failed_case_ids") == []
        and len(validations) == len(cases)
    ):
        failures.append("source_verification.status")
    return failures


def validate_micro_replays(payload: Mapping[str, Any], root: Path) -> list[str]:
    failures: list[str] = []
    results = payload.get("results", [])
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
        return ["micro_replays.results"]
    for result in results:
        if not isinstance(result, Mapping):
            failures.append("micro_replays.result")
            continue
        source = PurePosixPath(str(result.get("source", "")))
        if source.is_absolute() or ".." in source.parts or not (root / source).is_file():
            failures.append(f"micro_replays.source.{result.get('case_id')}")
            continue
        if result.get("source_sha256") != hashlib.sha256((root / source).read_bytes()).hexdigest():
            failures.append(f"micro_replays.source_digest.{result.get('case_id')}")
        try:
            stdout = json.loads(str(result.get("stdout", "")))
        except json.JSONDecodeError:
            stdout = {}
        observed = result.get("observed", {})
        if not (
            result.get("passed") is True
            and result.get("returncode") == 0
            and stdout == observed
            and observed.get("case_id") == result.get("case_id")
            and observed.get("before_defect_observed") is True
            and observed.get("after_expectation_passed") is True
        ):
            failures.append(f"micro_replays.execution.{result.get('case_id')}")
    if not (
        payload.get("status") == "passed"
        and payload.get("fixture_count") == len(results) == 3
        and payload.get("language_count") == len({item.get("language") for item in results}) == 3
    ):
        failures.append("micro_replays.status")
    return failures


def validate_container_isolation(payload: Mapping[str, Any]) -> list[str]:
    controls = payload.get("security_controls", {})
    result = payload.get("result", {})
    command = result.get("command", []) if isinstance(result, Mapping) else []
    rendered = " ".join(str(item) for item in command)
    stderr = str(result.get("stderr", "")) if isinstance(result, Mapping) else ""
    base = payload.get("base_image", {})
    expected_flags = payload.get("expected_flags", {})
    required_fragments = (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--pids-limit 64",
        "--memory 256m",
        "--cpus 0.50",
    )
    if not (
        payload.get("executed") is True
        and payload.get("passed") is True
        and isinstance(controls, Mapping)
        and controls
        and all(value is True for value in controls.values())
        and isinstance(result, Mapping)
        and result.get("returncode") == 0
        and result.get("timed_out") is False
        and all(fragment in rendered for fragment in required_fragments)
        and isinstance(expected_flags, Mapping)
        and set(expected_flags) == set(controls)
        and isinstance(base, Mapping)
        and base.get("reference") == "python:3.12-slim"
        and isinstance(base.get("repo_digests"), list)
        and len(base["repo_digests"]) == 1
        and str(base["repo_digests"][0]).startswith("python@sha256:")
        and str(base.get("image_id", "")).startswith("sha256:")
        and payload.get("result_stdout_sha256")
        == hashlib.sha256(str(result.get("stdout", "")).encode()).hexdigest()
        and payload.get("result_stderr_sha256") == hashlib.sha256(stderr.encode()).hexdigest()
        and all(name in stderr for name in ("test_env", "test_network", "test_rootfs"))
        and "Ran 3 tests" in stderr
        and stderr.rstrip().endswith("OK")
        and payload.get("expected_tests") == ["test_env", "test_network", "test_rootfs"]
    ):
        return ["container_isolation.semantic_validation"]
    return []


def validate_core_evidence(
    *,
    root: Path,
    resilient: Mapping[str, Any],
    model: Mapping[str, Any],
    faultbench: Mapping[str, Any],
    sources: Mapping[str, Any],
    micro: Mapping[str, Any],
    isolation: Mapping[str, Any],
) -> list[str]:
    dataset = root / "faultbench/cases.json"
    return [
        *validate_resilient_matrix(resilient),
        *validate_quorum_model(model),
        *validate_faultbench(faultbench, dataset),
        *validate_source_verification(sources, dataset),
        *validate_micro_replays(micro, root),
        *validate_container_isolation(isolation),
    ]


__all__ = [
    "canonical_digest",
    "validate_container_isolation",
    "validate_core_evidence",
    "validate_faultbench",
    "validate_micro_replays",
    "validate_quorum_model",
    "validate_resilient_matrix",
    "validate_source_verification",
]
