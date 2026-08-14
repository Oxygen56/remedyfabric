# Architecture

## Core boundary

RemedyFabric separates repair generation from deterministic control. A provider
may be rule-based, local-model, hosted API, or AgentTeams Worker. Regardless of
provider, the champion protocol accepts only a typed `PatchCandidate`; a Worker
cannot authorize release, count twice, or suppress the control-plane checks.

## State machine

`incident → isolated proposals → typed ingress → isolated staging → tests/challenge/policy → bound quorum → authorized materialization → post-materialization verification → release receipt | untouched/restored baseline`

Every retained transition is bound to the run, candidate and pre-change snapshot;
the legacy demo also appends hash-chained JSONL records. Before authorization,
candidate bytes exist only in a disposable symlink-preserving staging copy. The
governed workspace is materialized only after two Worker proposals, two
Verifier approvals, Challenger approval, Governor approval and a request from
the separately registered Release Manager bind to the same context. Full-set
old-content/path checks run before writes; failed authorized materialization or
post-verification restores the captured bytes.

## Context mechanisms

The system implements at least two required context capabilities:

1. **Shared structured state**: immutable `Incident`, `PatchCandidate`, `PolicyDecision`, `CommandResult`, and `RunResult` contracts carry context without free-form memory laundering.
2. **Trace/evidence observability**: commands, decisions, edits, results, hashes
   and terminal outcomes are preserved in structured receipts; the legacy demo
   uses an append-only hash-chained JSONL ledger and the champion matrix uses
   content-bound JSON trial receipts.

The local runtime deliberately does not use RAG. A future production adapter may add an authorized runbook store without changing the core contracts.

## AgentTeams mapping

The official-shape AgentTeams CRDs define an orchestration-only leader, two
role-separated proposers, two Verifiers, a Challenger, a Governor, and a
separately authorized Release Manager. These role names establish intended
authority separation, not independent fault domains. Together these are eight
Worker containers, alongside the official Controller and Manager. A complete
live result is claimed only if `artifacts/agentteams-live-evidence.json` exists
and passes strict validation. In that case it binds an adapter-assisted,
operator-captured Matrix typed protocol, two real recovery-Skill proposer
executions, two Verifiers, lead reviewer, Challenger, Governor, and an actual
Release Manager `QuorumGate` execution. It does not claim LLM-autonomous
orchestration. If the receipt is missing or invalid, the older blocked attempt
remains diagnostic only. The deterministic runtime performs the byte-level
champion transaction without AgentTeams, a model, credentials, or network access.

## Replacement cost

Replacing the repair provider requires implementing one method that returns
`PatchCandidate`. Replacing AgentTeams requires preserving task trigger,
delegation, proposal, Skill/tool execution, verification, review, terminal
decision, Manager relay and evidence deposition. Replacing the receipt backend
must preserve canonical content, actor/role/context binding and tamper detection.
These are component replacement boundaries, not evidence that their failures
are statistically or operationally independent.
