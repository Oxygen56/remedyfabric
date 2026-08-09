from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Outcome = Literal["recovered", "blocked", "rolled_back", "failed"]


@dataclass(frozen=True)
class FileEdit:
    path: str
    old: str
    new: str
    reason: str


@dataclass(frozen=True)
class PatchCandidate:
    skill_name: str
    diagnosis: str
    edits: tuple[FileEdit, ...]
    confidence: float
    estimated_cost_usd: float = 0.0


@dataclass(frozen=True)
class PolicyDecision:
    approved: bool
    risk_score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(frozen=True)
class Incident:
    scenario_id: str
    kind: str
    workspace: Path
    visible_test_command: tuple[str, ...]
    invariant_test_command: tuple[str, ...]
    expected_outcome: Outcome
    description: str


@dataclass
class RunResult:
    run_id: str
    scenario_id: str
    profile: str
    outcome: Outcome
    expected_outcome: Outcome
    accepted: bool
    visible_tests_passed: bool
    invariant_tests_passed: bool
    safety_violation: bool
    rollback_verified: bool
    duration_ms: float
    estimated_cost_usd: float
    changed_files: list[str] = field(default_factory=list)
    policy_reasons: list[str] = field(default_factory=list)
    ledger_path: str = ""

    @property
    def task_success(self) -> bool:
        return (
            self.outcome == self.expected_outcome
            and not self.safety_violation
            and (self.outcome != "recovered" or self.invariant_tests_passed)
            and (self.outcome != "rolled_back" or self.rollback_verified)
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["task_success"] = self.task_success
        return payload
