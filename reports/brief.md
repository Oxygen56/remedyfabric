# GOAI 2026 Agent Infra Delivery Brief

## Objective

Win the Agent Infra track and compete for the overall grand prize with a judge-runnable infrastructure project, not a thin product wrapper.

## Deadline and freeze

- Official initial submission deadline: **2026-08-16 23:59, UTC+8 / Asia/Shanghai**.
- Internal freeze: **2026-08-15 23:59, UTC+8 / Asia/Shanghai**.
- Official rules and handbook remain the controlling source; schedule changes require a fresh check.

## Problem contract

Autonomous repair agents can generate plausible patches, but teams lack an infrastructure layer that proves what failed, limits blast radius, role-separates validation, rolls back failure, and produces inspectable evidence. RemedyFabric treats repair as a controlled transaction across three proposal Workers, two Verifiers, a Challenger, a Governor, and a separately authorized Release Manager.

Success means a judge can clone the repository, run one command without credentials, observe both successful repairs and adversarial rejection/rollback, inspect receipts, and reproduce every reported metric.

## Scope

- AgentTeams-aligned leader, dual proposers, dual Verifiers, Challenger, Governor, and Release Manager identities.
- Typed patch Skill contract, deterministic offline provider and replaceable model-provider boundary.
- Isolated bounded command execution, policy decision, snapshot, rollback and hash-chained evidence.
- Transparent 22-trial repository matrix, 20,748-state finite checker, negative controls, and four comparison profiles.
- Public Apache-2.0 repository, documentation, dashboard and video.

## Non-goals

- Claiming universal automated program repair.
- Claiming production adoption, independent benchmark superiority, or zero risk.
- Using private datasets, hidden paid APIs or undeclared cloud resources.
- Starting another GOAI track before this entry is complete and reusable.

## Evidence gates

1. All tests pass from a clean environment.
2. Benchmark reruns deterministically and writes the run ledger.
3. Full profile beats the single-agent and relevant ablations on task success or safety.
4. Dashboard numbers exactly match benchmark JSON.
5. Public repository is cloneable and CI is green.
6. Video shows a real clean run; no mocked terminal output.
7. Submission receipt or success page is captured before claiming submission.
