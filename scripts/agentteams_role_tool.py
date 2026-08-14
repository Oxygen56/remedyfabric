#!/usr/bin/env python3
"""Execute one bounded RemedyFabric role operation inside an official Worker.

This adapter emits typed JSON only.  It never contacts a cloud API, writes the
governed repository, or lets a role exercise another role's authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# The helper is copied as a small source bundle into an official Worker.  Make
# that bundle self-contained instead of relying on an unrecorded PYTHONPATH in
# Docker ExecCreate.
SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from remedyfabric.faults import (
    AgentIdentity,
    AgentRole,
    Attestation,
    EvidenceBinding,
    EvidenceKind,
    Verdict,
    canonical_digest,
)
from remedyfabric.models import FileEdit, Incident, PatchCandidate
from remedyfabric.policy import RecoveryPolicy
from remedyfabric.quorum import CandidateProposal, QuorumGate, patch_digest
from remedyfabric.skills import RuleBasedRecoverySkill
from remedyfabric.snapshot import WorkspaceSnapshot

EXPECTED_OLD = (
    "def mean(values):\n"
    '    """Return the arithmetic mean, including the empty-input contract."""\n'
    "    return sum(values) / len(values)\n"
)
EXPECTED_NEW = (
    "def mean(values):\n"
    '    """Return the arithmetic mean, including the empty-input contract."""\n'
    "    if not values:\n"
    "        return 0.0\n"
    "    return sum(values) / len(values)\n"
)
MEMBERS = (
    AgentIdentity("rf-proposer-a", AgentRole.WORKER),
    AgentIdentity("rf-proposer-b", AgentRole.WORKER),
    AgentIdentity("rf-verifier", AgentRole.VERIFIER),
    AgentIdentity("rf-verifier-b", AgentRole.VERIFIER),
    AgentIdentity("rf-challenger", AgentRole.CHALLENGER),
    AgentIdentity("rf-governor", AgentRole.GOVERNOR),
    AgentIdentity("rf-release-manager", AgentRole.RELEASE_MANAGER),
)
_TEST_COUNT = re.compile(r"Ran\s+(\d+)\s+tests?\b")


def _candidate(payload: dict[str, Any] | None = None) -> PatchCandidate:
    if payload is None:
        return PatchCandidate(
            "remedyfabric-recovery",
            "visible empty-input contract failed",
            (FileEdit("app/service.py", EXPECTED_OLD, EXPECTED_NEW, "guard empty input"),),
            0.95,
            skill_version="0.1.0",
            provider_name="rule-based",
            provider_version="1.0.0",
        )
    return PatchCandidate(
        str(payload["skill_name"]),
        str(payload["diagnosis"]),
        tuple(FileEdit(**edit) for edit in payload["edits"]),
        float(payload["confidence"]),
        float(payload.get("estimated_cost_usd", 0.0)),
        str(payload["skill_version"]),
        str(payload["provider_name"]),
        str(payload["provider_version"]),
    )


def _candidate_payload(candidate: PatchCandidate) -> dict[str, Any]:
    return {
        "skill_name": candidate.skill_name,
        "diagnosis": candidate.diagnosis,
        "edits": [edit.__dict__ for edit in candidate.edits],
        "confidence": candidate.confidence,
        "estimated_cost_usd": candidate.estimated_cost_usd,
        "skill_version": candidate.skill_version,
        "provider_name": candidate.provider_name,
        "provider_version": candidate.provider_version,
    }


def _attestation(payload: dict[str, Any]) -> Attestation:
    binding = EvidenceBinding(
        str(payload["run_id"]),
        str(payload["candidate_digest"]),
        str(payload["snapshot_digest"]),
        EvidenceKind(str(payload["evidence_kind"])),
        str(payload["artifact_digest"]),
    )
    return Attestation(
        AgentIdentity(str(payload["actor_id"]), AgentRole(str(payload["role"]))),
        Verdict(str(payload["verdict"])),
        binding,
        str(payload["claimed_binding_digest"]),
        str(payload.get("detail", "")),
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
        "detail": attestation.detail,
    }


def _proposal(payload: dict[str, Any], candidate: PatchCandidate) -> CandidateProposal:
    return CandidateProposal(
        AgentIdentity(str(payload["actor_id"]), AgentRole(str(payload["role"]))),
        str(payload["run_id"]),
        str(payload["snapshot_digest"]),
        candidate,
        str(payload["claimed_patch_digest"]),
    )


def _receipt_inputs(payload: dict[str, Any], *, minimum: int) -> list[str]:
    receipts = [str(item) for item in payload.get("input_receipt_digests", [])]
    if (
        len(receipts) < minimum
        or len(receipts) != len(set(receipts))
        or any(
            len(item) != 64 or any(char not in "0123456789abcdef" for char in item)
            for item in receipts
        )
    ):
        raise ValueError("role input receipt set is invalid")
    return sorted(receipts)


def _snapshot_digest(files: dict[str, bytes], modes: dict[str, int]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(files):
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(modes[relative].to_bytes(4, "big"))
        digest.update(files[relative])
    return digest.hexdigest()


def _staged_candidate_evidence(workspace: Path, candidate: PatchCandidate) -> dict[str, Any]:
    """Prove the tested tree is exactly one candidate applied to the bound snapshot."""

    current = WorkspaceSnapshot.capture(workspace)
    prechange_files = dict(current.files)
    edit_paths: list[str] = []
    for edit in candidate.edits:
        if edit.path in edit_paths or edit.path not in current.files:
            raise ValueError("candidate edit is missing or duplicated in the staged workspace")
        try:
            current_text = current.files[edit.path].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("candidate target is not UTF-8 source") from error
        if current_text != edit.new:
            raise ValueError("staged workspace does not contain the candidate output")
        prechange_files[edit.path] = edit.old.encode("utf-8")
        edit_paths.append(edit.path)
    if not edit_paths:
        raise ValueError("candidate contains no executable edits")
    test_files = {
        relative: hashlib.sha256(content).hexdigest()
        for relative, content in sorted(current.files.items())
        if relative.startswith(("tests/", "invariants/")) and relative.endswith(".py")
    }
    if not any(path.startswith("tests/") for path in test_files) or not any(
        path.startswith("invariants/") for path in test_files
    ):
        raise ValueError("staged workspace lacks both visible and invariant tests")
    return {
        "candidate_digest": patch_digest(candidate),
        "derived_prechange_snapshot_digest": _snapshot_digest(prechange_files, current.modes),
        "staged_snapshot_digest": current.digest,
        "candidate_edit_paths": edit_paths,
        "test_file_sha256": test_files,
    }


def _stage_candidate(workspace: Path, candidate: PatchCandidate, snapshot: str) -> dict[str, Any]:
    """Validate the faulty tree, apply once, and return the exact staged binding."""

    from remedyfabric.skills import apply_candidate

    before = WorkspaceSnapshot.capture(workspace)
    if before.digest != snapshot:
        raise ValueError("faulty workspace does not match the bound snapshot")
    apply_candidate(workspace, candidate)
    staged = _staged_candidate_evidence(workspace, candidate)
    if staged["derived_prechange_snapshot_digest"] != snapshot:
        raise ValueError("staged workspace is not derived from the bound snapshot")
    return staged


def _test_count(result: subprocess.CompletedProcess[str]) -> int:
    matches = _TEST_COUNT.findall(f"{result.stdout}\n{result.stderr}")
    if len(matches) != 1:
        return 0
    return int(matches[0])


def _test_cases(result: subprocess.CompletedProcess[str]) -> list[dict[str, str]]:
    cases: dict[str, str] = {}
    for line in f"{result.stdout}\n{result.stderr}".splitlines():
        # unittest -v emits `method (module.Class.method) ... ok`; bind the
        # executed identities without preserving nondeterministic timing.
        match = re.match(r"^\S+\s+\(([^)]+)\)\s+\.\.\.\s+(.+)$", line.strip())
        if match:
            cases[match.group(1)] = match.group(2).strip()
    return [{"test_id": test_id, "status": cases[test_id]} for test_id in sorted(cases)]


def _run_negative_control(workspace: Path) -> dict[str, Any]:
    """Show the invariant suite rejects a deterministic overfit mutant."""

    with tempfile.TemporaryDirectory(prefix="remedyfabric-negative-") as temporary:
        mutant = Path(temporary) / "workspace"
        shutil.copytree(workspace, mutant)
        source = mutant / "app/service.py"
        source.write_text(
            'def mean(values):\n    """Deliberately unsafe challenger mutant."""\n    return 0.0\n',
            encoding="utf-8",
        )
        command = [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "invariants",
            "-v",
        ]
        result = subprocess.run(
            command,
            cwd=mutant,
            text=True,
            capture_output=True,
            check=False,
        )
        count = _test_count(result)
        cases = _test_cases(result)
        rejected = result.returncode != 0 and count > 0 and len(cases) == count
        return {
            "mutation": "replace app/service.py with constant-zero overfit",
            "mutated_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "command": ["python", *command[1:]],
            "returncode": result.returncode,
            "test_count": count,
            "test_cases": cases,
            "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            "rejected": rejected,
        }


def execute(role: str, payload: dict[str, Any]) -> dict[str, Any]:
    actor = str(payload["actor_id"])
    run_id = str(payload["run_id"])
    snapshot = str(payload["snapshot_digest"])
    candidate = _candidate(payload.get("candidate"))
    candidate_id = patch_digest(candidate)
    if role == "proposer":
        if actor not in {"rf-proposer-a", "rf-proposer-b"}:
            raise ValueError("proposer actor is not authorized")
        workspace = Path(str(payload["workspace"]))
        source = workspace / "app/service.py"
        source.parent.mkdir(parents=True, exist_ok=True)
        if not source.exists():
            source.write_text(EXPECTED_OLD, encoding="utf-8")
        incident = Incident(
            scenario_id=run_id,
            kind="empty_mean",
            workspace=workspace,
            visible_test_command=(sys.executable, "-m", "unittest", "discover", "-s", "tests"),
            invariant_test_command=(
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "invariants",
            ),
            expected_outcome="recovered",
            description="empty mean must return zero while preserving non-empty semantics",
        )
        observed_snapshot = WorkspaceSnapshot.capture(workspace)
        if observed_snapshot.digest != snapshot:
            raise ValueError("proposer workspace does not match the bound snapshot")
        candidate = RuleBasedRecoverySkill().propose(
            incident, "visible empty-input contract failed"
        )
        candidate_id = patch_digest(candidate)
        produced = candidate.skill_name == RuleBasedRecoverySkill.name and bool(candidate.edits)
        proposal = CandidateProposal.issue(
            AgentIdentity(actor, AgentRole.WORKER), run_id, snapshot, candidate
        )
        return {
            "produced_by_bound_skill": produced,
            "skill_contract_path": "skills/remedyfabric-recovery/SKILL.md",
            "patch_candidate": _candidate_payload(candidate),
            "candidate_digest": candidate_id,
            "observed_snapshot_digest": observed_snapshot.digest,
            "proposal": {
                "actor_id": actor,
                "role": "worker",
                "run_id": run_id,
                "snapshot_digest": snapshot,
                "claimed_patch_digest": proposal.claimed_patch_digest,
            },
        }
    if role in {"verifier", "challenger"}:
        expected_actor = {
            "verifier": {"rf-verifier", "rf-verifier-b"},
            "challenger": {"rf-challenger"},
        }[role]
        if actor not in expected_actor:
            raise ValueError(f"{role} actor is not authorized")
        consumed_receipts = _receipt_inputs(payload, minimum=2)
        workspace = Path(str(payload["workspace"]))
        staged_evidence = _stage_candidate(workspace, candidate, snapshot)
        commands = [
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "invariants", "-v"],
        ]
        results = [
            subprocess.run(command, cwd=workspace, text=True, capture_output=True, check=False)
            for command in commands
        ]
        test_counts = [_test_count(result) for result in results]
        test_cases = [_test_cases(result) for result in results]
        passed = (
            all(result.returncode == 0 for result in results)
            and all(count > 0 for count in test_counts)
            and all(
                len(cases) == count and all(case["status"] == "ok" for case in cases)
                for cases, count in zip(test_cases, test_counts, strict=True)
            )
        )
        artifact = {
            "actor_id": actor,
            "commands": [["python", *command[1:]] for command in commands],
            "returncodes": [result.returncode for result in results],
            "test_counts": test_counts,
            "test_cases": test_cases,
            "stdout_sha256": [
                hashlib.sha256(result.stdout.encode()).hexdigest() for result in results
            ],
            "stderr_sha256": [
                hashlib.sha256(result.stderr.encode()).hexdigest() for result in results
            ],
            "workspace_binding": staged_evidence,
        }
        if role == "challenger":
            visible_ids = {case["test_id"] for case in test_cases[0]}
            invariant_ids = {case["test_id"] for case in test_cases[1]}
            negative_control = _run_negative_control(workspace)
            artifact["negative_control"] = negative_control
            artifact["test_and_invariant_suites_distinct"] = visible_ids.isdisjoint(invariant_ids)
            passed = bool(
                passed
                and negative_control["rejected"]
                and artifact["test_and_invariant_suites_distinct"]
            )
        kind = EvidenceKind.TEST if role == "verifier" else EvidenceKind.CHALLENGE
        identity_role = AgentRole.VERIFIER if role == "verifier" else AgentRole.CHALLENGER
        attestation = Attestation.issue(
            AgentIdentity(actor, identity_role),
            Verdict.APPROVE if passed else Verdict.REJECT,
            EvidenceBinding(run_id, candidate_id, snapshot, kind, canonical_digest(artifact)),
            "bounded visible and invariant execution",
        )
        return {
            "artifact": artifact,
            "attestation": _attestation_payload(attestation),
            "consumed_receipt_digests": consumed_receipts,
        }
    if role == "reviewer":
        if actor != "rf-lead":
            raise ValueError("reviewer actor is not authorized")
        proposals = [_proposal(item, candidate) for item in payload["proposals"]]
        expected_actors = {"rf-proposer-a", "rf-proposer-b"}
        observed_actors = {proposal.identity.actor_id for proposal in proposals}
        proposal_validity = [
            proposal.integrity_valid
            and proposal.run_id == run_id
            and proposal.snapshot_digest == snapshot
            and proposal.claimed_patch_digest == candidate_id
            for proposal in proposals
        ]
        converged = (
            len(proposals) == 2 and observed_actors == expected_actors and all(proposal_validity)
        )
        consumed_receipts = _receipt_inputs(payload, minimum=2)
        artifact = {
            "actor_id": actor,
            "candidate_digest": candidate_id,
            "expected_proposer_actors": sorted(expected_actors),
            "observed_proposer_actors": sorted(observed_actors),
            "proposal_integrity": proposal_validity,
            "proposal_receipt_digests": consumed_receipts,
            "converged": converged,
            "authority_boundary": "review-only; not a quorum attestation or release authority",
        }
        if not converged:
            raise ValueError("reviewer rejected non-converged proposals")
        return {
            "artifact": artifact,
            "review_receipt_digest": canonical_digest(artifact),
            "consumed_receipt_digests": consumed_receipts,
        }
    if role == "governor":
        if actor != "rf-governor":
            raise ValueError("governor actor is not authorized")
        consumed_receipts = _receipt_inputs(payload, minimum=2)
        workspace = Path(str(payload["workspace"]))
        staged_evidence = _stage_candidate(workspace, candidate, snapshot)
        policy = RecoveryPolicy().evaluate(workspace, candidate)
        artifact = {
            "approved": policy.approved,
            "risk_score": policy.risk_score,
            "reasons": list(policy.reasons),
            "workspace_binding": staged_evidence,
        }
        attestation = Attestation.issue(
            AgentIdentity(actor, AgentRole.GOVERNOR),
            Verdict.APPROVE if policy.approved else Verdict.REJECT,
            EvidenceBinding(
                run_id, candidate_id, snapshot, EvidenceKind.POLICY, canonical_digest(artifact)
            ),
            f"risk_score={policy.risk_score}",
        )
        return {
            "artifact": artifact,
            "attestation": _attestation_payload(attestation),
            "consumed_receipt_digests": consumed_receipts,
        }
    if role == "release-manager":
        if actor != "rf-release-manager":
            raise ValueError("release-manager actor is not authorized")
        consumed_receipts = _receipt_inputs(payload, minimum=7)
        proposals = [_proposal(item, candidate) for item in payload["proposals"]]
        decision = QuorumGate(MEMBERS).evaluate(
            run_id=run_id,
            snapshot_digest=snapshot,
            candidate=candidate,
            proposals=proposals,
            attestations=[_attestation(item) for item in payload["attestations"]],
            requested_by=AgentIdentity(actor, AgentRole.RELEASE_MANAGER),
        )
        return {
            "decision": decision.to_dict(),
            "consumed_receipt_digests": consumed_receipts,
        }
    if role == "alibaba-cloud-preflight":
        if actor != "rf-verifier":
            raise ValueError("cloud preflight actor is not authorized")
        consumed_receipts = _receipt_inputs(payload, minimum=2)
        credential_names = ("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET")
        missing = [name for name in credential_names if not os.environ.get(name)]
        return {
            "skill": "alibabacloud-resourcecenter-search",
            "status": "blocked_before_cloud_api" if missing else "credentials-present-stop",
            "reason_code": "missing_credentials" if missing else "manual_authorization_required",
            "credential_present": not missing,
            "request_sent": False,
            "cost_usd": 0,
            "consumed_receipt_digests": consumed_receipts,
        }
    raise ValueError(f"unsupported role operation: {role}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    result = execute(args.role, json.loads(args.input.read_text(encoding="utf-8")))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return (
        2 if args.role == "alibaba-cloud-preflight" and result["credential_present"] is False else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
