# GOAI 2026 Agent Infra score mapping

This document maps retained evidence to the five published Agent Infra scoring
dimensions. It is an artifact map, not a predicted score.

## One-sentence winning thesis

**RemedyFabric keeps repository recovery safe when the repair Agents themselves
fail: one faulty Worker cannot authorize release, honest Workers retain liveness,
and tested overflow conditions restore the exact pre-change bytes.**

## Evidence-to-score map

| Official dimension | Weight | Judge-facing answer | Retained evidence | Honest remaining gap |
| --- | ---: | --- | --- | --- |
| Scenario value and replicability | 25% | Agent-driven source repair is valuable only if teams can trust the repair control plane. RemedyFabric is provider-neutral infrastructure for isolated repositories, with a zero-credential replay path and explicit unsupported-case behavior. | [`README.md`](../README.md), [`artifacts/resilient-matrix.json`](../artifacts/resilient-matrix.json), [`docs/JUDGE_GUIDE.md`](JUDGE_GUIDE.md), [`artifacts/benchmark.json`](../artifacts/benchmark.json) | The 22 executable trials use fresh authored repository fixtures, not 22 complete upstream applications. Production incident coverage is not claimed. |
| Multi-Agent collaboration and autonomous loop | 25% | The deterministic path uses three Workers, two Verifiers, a Challenger, a Governor, and a separately authorized Release Manager. Conditional strict live evidence adds official AgentTeams v1.2.2 Controller + Manager + 8 Worker containers and a typed Matrix DAG across two proposers, two Verifiers, lead reviewer, Challenger, Governor, and Release Manager. | 22 executable repository trials plus, only if present and valid, `artifacts/agentteams-live-evidence.json` | Roles are separately authorized but share implementation/provider boundaries. The live capture is adapter-assisted/operator-captured and does not claim LLM-autonomous orchestration or independent fault domains. |
| Skill engineering and reuse | 25% | `remedyfabric-recovery` is a versioned, model-neutral Skill with typed `PatchCandidate` output, old-content preconditions, failure modes, policy boundaries, and a replaceable provider contract. The same typed messages drive runtime and benchmark gates. | [`skills/remedyfabric-recovery/SKILL.md`](../skills/remedyfabric-recovery/SKILL.md), [`src/remedyfabric/models.py`](../src/remedyfabric/models.py), [`src/remedyfabric/quorum.py`](../src/remedyfabric/quorum.py), [`agentteams/remedyfabric-live-local.yaml`](../agentteams/remedyfabric-live-local.yaml) | The official Alibaba Cloud Skill is pinned/package-verified; only a strict live receipt can credit its adapter-executed no-credential preflight, and no cloud query is claimed. |
| Engineering, verification, safety and audit | 20% | The implementation combines typed authority, 2-of-3 proposal convergence, isolated staging, pre-write policy/quorum, real visible/invariant execution, challenge, SHA-256 context binding, deterministic release receipts, container boundary probes, and byte-exact recovery. | 8 single-Worker modes: 100% recovery and 0 unsafe release; 13 overflow/control trials: 100% fail closed; traversal and symlink collusion produce 0 external-byte changes; 20,748 checked small-model decisions; 30-case protocol simulation; three semantic micro-replays; container probe passed. See evidence index below. | SHA-256 is not an actor signature. The finite state space is not a formal BFT proof. Frozen-release proof remains pending until its post-HEAD CI artifact and release-ZIP receipts validate. |
| Open/open-source contribution | 5% | Apache-2.0 source, tests, manifests, authored fixtures, protocol corpus, minimized comparison receipts, threat model, disclosure, and reproducible judge commands are included. | [`LICENSE`](../LICENSE), [`CONTRIBUTING.md`](../CONTRIBUTING.md), [`docs/DISCLOSURE.md`](DISCLOSURE.md), [`docs/SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md), public repository [Oxygen56/remedyfabric](https://github.com/Oxygen56/remedyfabric) | A public URL proves availability, not that a local unpushed change or future release has passed CI. Judge claims should be tied to the submitted commit and retained artifacts. |

## Quantitative score evidence

### 1. Executable faulty-Worker recovery

[`artifacts/resilient-matrix.json`](../artifacts/resilient-matrix.json) contains
22 fresh isolated repository trials:

- 1 no-fault baseline: 100% recovery;
- 8 single-Worker fault modes—crash, equivocation, forged proposal, replay,
  unsafe patch, context mismatch, role impersonation, and timeout: 100% recovery,
  100% relative recovery versus baseline, and 0 unsafe releases;
- 13 enumerated two-fault/control-failure trials: 100% fail-closed behavior,
  zero pre-authorization governed-workspace writes, and zero external-byte
  violations; and
- every trial terminates in either an authorized release or a verified
  byte-exact non-release state (untouched baseline or restoration).

These are real filesystem transactions and real `unittest` executions against
fresh authored repository fixtures. They are not simulations of a decision
label, and they are not full upstream repository reproductions.

### 2. Exhaustive finite-state safety check

[`artifacts/quorum-model.json`](../artifacts/quorum-model.json) records 20,748
checked decisions and zero violations for:

1. fewer than two distinct Workers cannot authorize;
2. a Worker cannot request release;
3. a control rejection cannot be overridden;
4. Worker equivocation cannot authorize;
5. control equivocation cannot authorize; and
6. forged or replayed evidence cannot authorize.

This is exhaustive only for the declared finite state space: three Workers, two
candidate patches, two Verifiers, one Challenger, one Governor, and two possible
requester identities. It is not a general or formal Byzantine consensus proof.

### 3. Provenance-bound protocol comparison

[`artifacts/faultbench-results.json`](../artifacts/faultbench-results.json)
contains 30 protocol-simulation cases and 120 case/profile trials across:

- 6 public repositories;
- Python, JavaScript, and Rust;
- 8 synthetic fault/attack classes;
- 23 cases inside the one-Worker fault claim and 7 overflow/control-plane controls; and
- single-agent, simple-majority, v0.1, and champion-quorum topologies.

The champion-quorum profile records 100% safe recovery and 0 unsafe release for
the 23 modeled one-Worker-fault cases, plus 100% containment for the seven overflow and
control-plane controls. Every result is derived from concrete `CandidateProposal`,
`Attestation`, and `QuorumGate` messages. These are protocol simulations, not
30 autonomous upstream repairs; latency and cost fields are declared proxies.

GitHub official REST metadata revalidation passed all 30 case records at the
recorded retrieval time in
[`artifacts/faultbench-source-verification.json`](../artifacts/faultbench-source-verification.json).
That receipt verifies metadata, not defect reproducibility or patch correctness.

### 4. Executed semantic anchors

[`artifacts/faultbench-micro-replays.json`](../artifacts/faultbench-micro-replays.json)
records three passing executions:

- Requests #7308: one Python regex-end semantic;
- Fastify #6838: one JavaScript HTTP-method normalization semantic; and
- axum #3848: one Rust opaque-byte validation semantic.

Each is an independently written standalone fixture derived from a linked public
diff. None imports the upstream package or runs the upstream test suite.

## Mandatory-design evidence status

The AgentTeams Worker/Team manifests and reusable Skill establish a concrete
deployment design. The table is deliberately conditional: successful-live rows
count only if `artifacts/agentteams-live-evidence.json` exists and passes the
strict validator.

| Evidence | Status used in this scorecard |
| --- | --- |
| Official v1.2.2 Controller + Manager + 8 Worker containers | **Claimed only by a valid strict live artifact** |
| Typed Manager/Matrix/Worker/Manager event chain | **Adapter-assisted and operator-captured; claimed only by a valid strict live artifact** |
| Role work | **Two real recovery-Skill proposers; two Verifiers; lead reviewer; Challenger; Governor; actual Release Manager `QuorumGate`, only if strictly validated** |
| Runtime-enforced ACL denial | **Must be bound into the same strict receipt; historical 403 remains diagnostic** |
| Deterministic local role-separated runtime | **Executed and retained** |
| `remedyfabric-recovery` Skill contract | **Implemented and retained** |
| Official Alibaba Cloud discovery Skill | **Pinned/package-verified; strict receipt may prove only an adapter-executed missing-credential preflight, never a cloud query** |

The live receipt binds local Ollama `gpt-oss:20b` digest
`17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7`
(20.9B, MXFP4, Apache-2.0), USD 0.00 model/API fees, and local compute. A
manifest, screenshot, role name, model HTTP response, or running container alone
must not be substituted for the strict receipt.

## Evidence index by official dimension

| Evidence | Value / collaboration | Skill / ecosystem | Engineering / safety | Open source |
| --- | :---: | :---: | :---: | :---: |
| [`artifacts/resilient-matrix.json`](../artifacts/resilient-matrix.json) | Yes | Typed contract | Primary | Raw JSON |
| [`artifacts/quorum-model.json`](../artifacts/quorum-model.json) | — | — | Primary | Raw JSON |
| [`artifacts/faultbench-results.json`](../artifacts/faultbench-results.json) | Cross-repository identities | Same message protocol | Baselines / ablation | Raw JSON + corpus |
| [`artifacts/faultbench-micro-replays.json`](../artifacts/faultbench-micro-replays.json) | Three-language anchors | — | Executed semantics | Source included |
| [`artifacts/container-isolation.json`](../artifacts/container-isolation.json) | — | — | Boundary probe | Raw JSON |
| `artifacts/agentteams-live-evidence.json` | Conditional official loop | Real Skill/control receipts | Strict semantic replay | Redacted raw evidence |
| Four post-HEAD receipts in the public v0.2.0 release ZIP | Frozen reinstall/replay and public-CI binding | — | Authoritative only after the exact CI artifact and `clean-replay.json`, `public-ci.json`, `champion-evidence.json`, and `champion-gate.json` all validate | Raw JSON + archive hashes; missing means pending |
| [`skills/remedyfabric-recovery/SKILL.md`](../skills/remedyfabric-recovery/SKILL.md) | Reusable workflow | Primary | Failure contract | Apache-2.0 |
| [`agentteams/remedyfabric-live-local.yaml`](../agentteams/remedyfabric-live-local.yaml) | Role design only | Skill assignment design | ACL design only | Manifest included |
| [`docs/SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md) | Trust boundary | Capability boundary | Claim limits / risks | Public review |
| [`docs/DISCLOSURE.md`](DISCLOSURE.md) | Reproducibility | External integrations | Cost / model / data | Rights / licenses |

## Claim boundary

The strongest supported statement is:

> In the retained authored executable matrix, RemedyFabric safely recovered in
> all eight tested one-Worker fault modes with zero unsafe release; in all 13
> enumerated overflow/control-failure trials it failed closed, with zero
> pre-authorization governed-workspace writes and zero external-byte violations.
> A separate finite checker found no counterexample in 20,748 decisions, while a
> 30-case provenance-bound corpus showed the same gate's topology behavior in
> protocol simulation.

Do not shorten this to “RemedyFabric is Byzantine fault tolerant,” “22 real-world
repositories were repaired,” “30 upstream bugs were reproduced,” or “production
safety is proven.” None of those claims is supported.

This scorecard does not infer final readiness from source text. The strict
AgentTeams receipt and final delivery bytes must be bound before source freeze.
The clean replay, public-CI receipt, champion manifest, and champion gate are
self-referential post-HEAD artifacts: the exact public CI artifact and public
v0.2.0 release ZIP are their authority. Until both carriers exist and every
receipt strictly validates, final readiness remains pending.
