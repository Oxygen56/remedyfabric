"""Fault vocabulary and evidence-bound attestations for quorum recovery.

The model is deliberately narrower than Byzantine fault-tolerant consensus.  It
models one registered repair worker that may crash, equivocate, replay evidence,
or submit arbitrary patches.  Control-plane actors are separately registered;
missing or contradictory control evidence makes the protocol fail closed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any


class AgentRole(str, Enum):
    """Non-overlapping capabilities used by the recovery protocol."""

    WORKER = "worker"
    VERIFIER = "verifier"
    CHALLENGER = "challenger"
    GOVERNOR = "governor"
    RELEASE_MANAGER = "release-manager"


class Verdict(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class EvidenceKind(str, Enum):
    TEST = "test"
    CHALLENGE = "challenge"
    POLICY = "policy"


class FaultMode(str, Enum):
    """Injectable, Byzantine-like behaviours used by the model checker."""

    CRASH = "crash"
    EQUIVOCATE = "equivocate"
    FORGE_EVIDENCE = "forge-evidence"
    REPLAY_EVIDENCE = "replay-evidence"
    APPROVE_UNSAFE = "approve-unsafe"


def canonical_digest(value: Any) -> str:
    """Return a deterministic SHA-256 digest for JSON-compatible evidence."""

    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


@dataclass(frozen=True)
class AgentIdentity:
    """A pre-registered actor and its single allowed protocol role."""

    actor_id: str
    role: AgentRole

    def __post_init__(self) -> None:
        if not self.actor_id or self.actor_id.strip() != self.actor_id:
            raise ValueError("actor_id must be a non-empty canonical identifier")


@dataclass(frozen=True)
class EvidenceBinding:
    """Binds one control result to a run, patch, and pre-change snapshot."""

    run_id: str
    candidate_digest: str
    snapshot_digest: str
    kind: EvidenceKind
    artifact_digest: str

    def payload(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "candidate_digest": self.candidate_digest,
            "snapshot_digest": self.snapshot_digest,
            "kind": self.kind.value,
            "artifact_digest": self.artifact_digest,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.payload())

    @property
    def has_valid_shape(self) -> bool:
        return bool(self.run_id) and all(
            is_sha256(value)
            for value in (self.candidate_digest, self.snapshot_digest, self.artifact_digest)
        )


@dataclass(frozen=True)
class Attestation:
    """A role-scoped verdict with a tamper-evident evidence fingerprint.

    This digest provides integrity and binding, not cryptographic actor
    authentication.  Production deployments must authenticate the registered
    actor through their execution/runtime identity.
    """

    identity: AgentIdentity
    verdict: Verdict
    binding: EvidenceBinding
    claimed_binding_digest: str
    detail: str = ""

    @classmethod
    def issue(
        cls,
        identity: AgentIdentity,
        verdict: Verdict,
        binding: EvidenceBinding,
        detail: str = "",
    ) -> Attestation:
        return cls(identity, verdict, binding, binding.digest, detail)

    @property
    def integrity_valid(self) -> bool:
        return self.binding.has_valid_shape and self.claimed_binding_digest == self.binding.digest

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                "actor_id": self.identity.actor_id,
                "role": self.identity.role.value,
                "verdict": self.verdict.value,
                "binding_digest": self.claimed_binding_digest,
                "detail": self.detail,
            }
        )


def inject_attestation_fault(
    attestation: Attestation,
    mode: FaultMode,
    *,
    alternate_candidate_digest: str | None = None,
) -> tuple[Attestation, ...]:
    """Create deterministic faulty artifacts for tests and exhaustive checks."""

    if mode is FaultMode.CRASH:
        return ()
    if mode is FaultMode.FORGE_EVIDENCE:
        return (replace(attestation, claimed_binding_digest="f" * 64),)
    if mode is FaultMode.REPLAY_EVIDENCE:
        replayed = replace(attestation.binding, run_id=f"replayed:{attestation.binding.run_id}")
        return (replace(attestation, binding=replayed, claimed_binding_digest=replayed.digest),)
    if mode is FaultMode.APPROVE_UNSAFE:
        return (replace(attestation, verdict=Verdict.APPROVE),)
    if mode is FaultMode.EQUIVOCATE:
        if alternate_candidate_digest is None or not is_sha256(alternate_candidate_digest):
            raise ValueError("equivocation requires a valid alternate_candidate_digest")
        alternate = replace(attestation.binding, candidate_digest=alternate_candidate_digest)
        return (
            attestation,
            replace(attestation, binding=alternate, claimed_binding_digest=alternate.digest),
        )
    raise ValueError(f"unsupported fault mode: {mode}")
