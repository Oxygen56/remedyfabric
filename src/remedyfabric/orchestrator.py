from __future__ import annotations

import time
import uuid
from pathlib import Path

from .agents import GovernorAgent, RepairAgent, TriageAgent, VerifierAgent
from .executor import SandboxExecutor
from .ledger import EvidenceLedger
from .models import Incident, RunResult
from .policy import RecoveryPolicy
from .skills import RuleBasedRecoverySkill, apply_candidate
from .snapshot import WorkspaceSnapshot

PROFILES = {
    "full": {"governor": True, "verifier": True, "rollback": True},
    "no-governor": {"governor": False, "verifier": True, "rollback": True},
    "no-verifier": {"governor": True, "verifier": False, "rollback": True},
    "no-rollback": {"governor": True, "verifier": True, "rollback": False},
    "single-agent": {"governor": False, "verifier": False, "rollback": False},
}


class RecoveryFabric:
    """Four-agent recovery state machine with fail-closed governance."""

    def __init__(self, evidence_root: Path) -> None:
        self.executor = SandboxExecutor()
        self.triage = TriageAgent(self.executor)
        self.repair = RepairAgent(RuleBasedRecoverySkill())
        self.governor = GovernorAgent(RecoveryPolicy())
        self.verifier = VerifierAgent(self.executor)
        self.evidence_root = evidence_root

    def run(self, incident: Incident, profile: str = "full") -> RunResult:
        if profile not in PROFILES:
            raise ValueError(f"unknown profile: {profile}")
        flags = PROFILES[profile]
        start = time.perf_counter()
        run_id = f"{incident.scenario_id}-{profile}-{uuid.uuid4().hex[:8]}"
        ledger_path = self.evidence_root / f"{run_id}.jsonl"
        ledger = EvidenceLedger(ledger_path, run_id)
        snapshot = WorkspaceSnapshot.capture(incident.workspace)
        ledger.append(
            "incident_received",
            "manager-agent",
            {
                "scenario_id": incident.scenario_id,
                "kind": incident.kind,
                "description": incident.description,
                "snapshot_digest": snapshot.digest,
                "profile": profile,
            },
        )

        diagnosis, before = self.triage.diagnose(incident, ledger)
        candidate = self.repair.propose(incident, diagnosis, ledger)
        if flags["governor"]:
            decision = self.governor.decide(incident, candidate, ledger)
        else:
            from .models import PolicyDecision

            decision = PolicyDecision(True, 0, ("governor ablated",))
            ledger.append("policy_bypassed", "manager-agent", {"profile": profile})

        if not decision.approved:
            ledger.append("run_blocked", "manager-agent", {"reasons": list(decision.reasons)})
            return RunResult(
                run_id=run_id,
                scenario_id=incident.scenario_id,
                profile=profile,
                outcome="blocked",
                expected_outcome=incident.expected_outcome,
                accepted=False,
                visible_tests_passed=before.passed,
                invariant_tests_passed=False,
                safety_violation=False,
                rollback_verified=snapshot.matches(incident.workspace),
                duration_ms=(time.perf_counter() - start) * 1000,
                estimated_cost_usd=candidate.estimated_cost_usd,
                policy_reasons=list(decision.reasons),
                ledger_path=str(ledger_path),
            )

        try:
            changed = apply_candidate(incident.workspace, candidate)
            ledger.append("patch_applied", "manager-agent", {"changed_files": changed})
        except (RuntimeError, OSError, UnicodeError) as exc:
            ledger.append("patch_apply_failed", "manager-agent", {"error": str(exc)})
            if flags["rollback"]:
                snapshot.restore(incident.workspace)
            return RunResult(
                run_id=run_id,
                scenario_id=incident.scenario_id,
                profile=profile,
                outcome="failed",
                expected_outcome=incident.expected_outcome,
                accepted=False,
                visible_tests_passed=False,
                invariant_tests_passed=False,
                safety_violation=True,
                rollback_verified=snapshot.matches(incident.workspace),
                duration_ms=(time.perf_counter() - start) * 1000,
                estimated_cost_usd=candidate.estimated_cost_usd,
                policy_reasons=[str(exc)],
                ledger_path=str(ledger_path),
            )

        protected = any(
            path.startswith(("tests/", "invariants/", ".github/")) or ".." in Path(path).parts
            for path in changed
        )
        if flags["verifier"]:
            visible, invariant = self.verifier.verify(incident, ledger)
        else:
            visible = before
            invariant = before
            ledger.append("verification_bypassed", "manager-agent", {"profile": profile})

        verified = visible.passed and invariant.passed
        if verified:
            outcome = "recovered"
            rollback_verified = False
            accepted = True
            ledger.append("recovery_committed", "manager-agent", {"changed_files": changed})
        elif flags["rollback"]:
            snapshot.restore(incident.workspace)
            rollback_verified = snapshot.matches(incident.workspace)
            outcome = "rolled_back"
            accepted = False
            ledger.append("recovery_rolled_back", "manager-agent", {"verified": rollback_verified})
        else:
            rollback_verified = False
            outcome = "failed"
            accepted = True
            ledger.append("unsafe_failure_retained", "manager-agent", {"profile": profile})

        return RunResult(
            run_id=run_id,
            scenario_id=incident.scenario_id,
            profile=profile,
            outcome=outcome,
            expected_outcome=incident.expected_outcome,
            accepted=accepted,
            visible_tests_passed=visible.passed,
            invariant_tests_passed=invariant.passed,
            safety_violation=protected,
            rollback_verified=rollback_verified,
            duration_ms=(time.perf_counter() - start) * 1000,
            estimated_cost_usd=candidate.estimated_cost_usd,
            changed_files=changed,
            policy_reasons=list(decision.reasons),
            ledger_path=str(ledger_path),
        )
