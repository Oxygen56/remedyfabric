from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from .models import PatchCandidate, PolicyDecision

SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]+"
)


class RecoveryPolicy:
    """Fail-closed policy for autonomous source changes."""

    def __init__(self, max_files: int = 4) -> None:
        self.max_files = max_files
        self.protected_roots = {"tests", "invariants", ".github", ".git"}
        self.protected_names = {".env", "LICENSE", "pyproject.toml"}
        self.allowed_roots = {"app", "src", "lib"}

    def evaluate(self, workspace: Path, candidate: PatchCandidate) -> PolicyDecision:
        reasons: list[str] = []
        risk = 0
        if not candidate.edits:
            reasons.append("candidate contains no edits")
            risk += 100
        if len(candidate.edits) > self.max_files:
            reasons.append(f"edit count {len(candidate.edits)} exceeds limit {self.max_files}")
            risk += 60

        for edit in candidate.edits:
            pure = PurePosixPath(edit.path)
            if pure.is_absolute() or ".." in pure.parts:
                reasons.append(f"path escapes workspace: {edit.path}")
                risk += 100
                continue
            resolved = (workspace / edit.path).resolve()
            try:
                resolved.relative_to(workspace.resolve())
            except ValueError:
                reasons.append(f"resolved path escapes workspace: {edit.path}")
                risk += 100
            if pure.parts and pure.parts[0] in self.protected_roots:
                reasons.append(f"protected root cannot be edited: {edit.path}")
                risk += 100
            if pure.name in self.protected_names:
                reasons.append(f"protected file cannot be edited: {edit.path}")
                risk += 100
            if not pure.parts or pure.parts[0] not in self.allowed_roots:
                reasons.append(f"path is outside allowed source roots: {edit.path}")
                risk += 40
            if SECRET_PATTERN.search(edit.new):
                reasons.append(f"possible secret introduced: {edit.path}")
                risk += 100
            if len(edit.new) > 20_000:
                reasons.append(f"edit too large for autonomous approval: {edit.path}")
                risk += 40

        return PolicyDecision(approved=risk == 0, risk_score=min(risk, 100), reasons=tuple(reasons))
