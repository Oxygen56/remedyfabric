# Architecture

## Core boundary

RemedyFabric separates probabilistic repair generation from deterministic control. A provider may be rule-based, local-model, commercial API, or AgentTeams Worker. Regardless of provider, it can only return a `PatchCandidate`; it cannot write files, approve itself, run privileged commands, commit, or suppress verification.

## State machine

`incident_received → diagnosis → patch_proposed → policy_decision → patch_applied → independent_verification → recovery_committed | recovery_rolled_back`

Every state transition is appended to an evidence ledger whose record hash includes the prior record hash. Old-content preconditions prevent applying a patch against stale source. The snapshot layer records every file before modification and restores it when independent verification fails.

## Context mechanisms

The system implements at least two required context capabilities:

1. **Shared structured state**: immutable `Incident`, `PatchCandidate`, `PolicyDecision`, `CommandResult`, and `RunResult` contracts carry context without free-form memory laundering.
2. **Trace/evidence observability**: all commands, decisions, edits, durations, results, costs, hashes and terminal outcomes are preserved in append-only JSONL receipts.

The local runtime deliberately does not use RAG. A future production adapter may add an authorized runbook store without changing the core contracts.

## AgentTeams mapping

The official AgentTeams CRDs define one Team Leader and four Workers. Local execution mirrors the same responsibility split. The AgentTeams layer is optional for the zero-credential demo and required for the full competition deployment evidence. See `agentteams/`.

## Replacement cost

Replacing the repair provider requires implementing one method that returns `PatchCandidate`. Replacing AgentTeams requires preserving the five typed transitions. Replacing the ledger backend requires preserving canonical JSON, sequence, prior hash and receipt hash fields. This keeps model, orchestration, storage and safety independently replaceable.

