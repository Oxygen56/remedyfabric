from __future__ import annotations

from dataclasses import asdict

from .executor import SandboxExecutor
from .ledger import EvidenceLedger
from .models import CommandResult, Incident, PatchCandidate, PolicyDecision
from .policy import RecoveryPolicy
from .skills import RuleBasedRecoverySkill


class TriageAgent:
    name = "triage-agent"

    def __init__(self, executor: SandboxExecutor) -> None:
        self.executor = executor

    def diagnose(self, incident: Incident, ledger: EvidenceLedger) -> tuple[str, CommandResult]:
        result = self.executor.run(incident.workspace, incident.visible_test_command)
        signal = (result.stderr or result.stdout)[-4000:]
        diagnosis = f"visible verification failed with exit={result.returncode}: {signal}"
        ledger.append("diagnosis", self.name, {"diagnosis": diagnosis, "command": asdict(result)})
        return diagnosis, result


class RepairAgent:
    name = "repair-agent"

    def __init__(self, skill: RuleBasedRecoverySkill) -> None:
        self.skill = skill

    def propose(self, incident: Incident, diagnosis: str, ledger: EvidenceLedger) -> PatchCandidate:
        candidate = self.skill.propose(incident, diagnosis)
        ledger.append(
            "patch_proposed",
            self.name,
            {
                "skill": candidate.skill_name,
                "confidence": candidate.confidence,
                "edits": [asdict(edit) for edit in candidate.edits],
                "estimated_cost_usd": candidate.estimated_cost_usd,
            },
        )
        return candidate


class GovernorAgent:
    name = "governor-agent"

    def __init__(self, policy: RecoveryPolicy) -> None:
        self.policy = policy

    def decide(
        self, incident: Incident, candidate: PatchCandidate, ledger: EvidenceLedger
    ) -> PolicyDecision:
        decision = self.policy.evaluate(incident.workspace, candidate)
        ledger.append("policy_decision", self.name, asdict(decision))
        return decision


class VerifierAgent:
    name = "verifier-agent"

    def __init__(self, executor: SandboxExecutor) -> None:
        self.executor = executor

    def verify(
        self, incident: Incident, ledger: EvidenceLedger
    ) -> tuple[CommandResult, CommandResult]:
        visible = self.executor.run(incident.workspace, incident.visible_test_command)
        invariant = self.executor.run(incident.workspace, incident.invariant_test_command)
        ledger.append(
            "independent_verification",
            self.name,
            {"visible": asdict(visible), "invariant": asdict(invariant)},
        )
        return visible, invariant
