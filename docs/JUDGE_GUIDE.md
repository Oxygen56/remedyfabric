# Judge guide: verify the standout claim in five minutes

## What to test first

The project is built around one falsifiable claim:

> A single faulty repair Worker cannot authorize its own patch. With two honest
> Workers, RemedyFabric still recovers; when the tested boundary is exceeded, it
> refuses release and retains or restores the captured pre-change bytes.

The fastest proof is not the video or dashboard. It is the executable resilience
matrix plus the separately executed finite-state checker.

## Minute 0–3: execute the champion path

Requirements: Python 3.11+ only. No account, API key, model, dataset download,
Docker daemon, Node.js, Rust, or network access is needed.

From the repository root:

```bash
PYTHONPATH=src python3 scripts/run_resilient_matrix.py \
  --output /tmp/remedyfabric-resilient.json
```

Expected terminal summary:

```text
passed: true
trial_count: 22
baseline_recovery_rate: 1.0
single_worker_trials: 8
single_worker_relative_recovery_vs_baseline: 1.0
single_worker_unsafe_releases: 0
tested_out_of_boundary_trials: 13
tested_out_of_boundary_fail_closed_rate: 1.0
preauthorization_workspace_write_attempts: 0
outside_write_violations: 0
```

This command does real work for every trial:

1. creates a fresh repository workspace and captures its byte-level snapshot;
2. runs the failing visible test;
3. lets three role-distinct Workers generate proposals in isolated clones;
4. injects the declared behavior into the selected actor without passing the
   fault label to proposal validation or the release gate;
5. applies the selected typed patch only to an isolated staging copy;
6. runs two distinct registered visible/invariant Verifier identities, a
   Challenger, and a Governor; these logical actors share one implementation and
   are not claimed as independent failure domains;
7. calls `QuorumGate` with a distinct Release Manager identity; and
8. materializes into the governed workspace only after authorization, otherwise
   verifies the untouched baseline bytes.

To inspect the most adversarial transaction—the two-Worker unsafe-patch
collusion that reaches proposal quorum, is staged, fails invariants, and never
touches the governed workspace—run:

```bash
python3 - <<'PY'
import json
data = json.load(open('/tmp/remedyfabric-resilient.json'))
trial = next(x for x in data['trials'] if x['trial_id'] == 'out-colluding-unsafe-workers')
print(json.dumps({
    'faults': trial['fault_injection'],
    'selected': trial['proposal_ingress']['selected_candidate_digest'],
    'staged': trial['filesystem_transaction']['candidate_staged_before_authorization'],
    'workspace_write_before_authorization': trial['filesystem_transaction']['workspace_write_attempted_before_authorization'],
    'workspace_materialized': trial['filesystem_transaction']['workspace_materialized_after_authorization'],
    'decision': trial['quorum_decision']['action'],
    'reason_codes': trial['reason_codes'],
    'rollback_byte_exact': trial['outcome']['rollback_verified_byte_exact'],
    'unsafe_release': trial['outcome']['unsafe_release'],
}, indent=2))
PY
```

The expected decision is `rollback`, `staged` is `true`, both workspace-write
fields are `false`, `rollback_byte_exact` is `true`, and `unsafe_release` is
`false`.

## Minute 3–4: exhaust the declared small model

```bash
PYTHONPATH=src python3 scripts/check_quorum_model.py \
  --output /tmp/remedyfabric-quorum-model.json
```

Expected result: `checked_decisions` is **20,748**, status is
`safe-within-model`, and every property has zero violations. Inspect directly:

```bash
python3 - <<'PY'
import json
data = json.load(open('/tmp/remedyfabric-quorum-model.json'))
print(data['checked_decisions'], data['status'])
print({name: item['violation_count'] for name, item in data['properties'].items()})
PY
```

This checker is exhaustive for its published finite state space. It is not a
general BFT proof.

## Minute 4–5: compare weaker topologies

```bash
PYTHONPATH=src python3 scripts/run_faultbench.py \
  --output /tmp/remedyfabric-faultbench.json
python3 - <<'PY'
import json
data = json.load(open('/tmp/remedyfabric-faultbench.json'))
for profile in data['profiles']:
    print(profile['profile'], {
        'single_fault_safe_recovery_rate': profile['single_fault_safe_recovery_rate'],
        'unsafe_release_rate': profile['unsafe_release_rate'],
        'overflow_containment_rate': profile['overflow_containment_rate'],
    })
PY
```

The champion-quorum row should show 100% modeled one-Worker-fault recovery, zero
unsafe release, and 100% overflow/control-plane containment across **23** cases
inside the one-Worker claim and **7** overflow/control cases. This is a 30-case
protocol-simulation corpus. It does not clone or execute the 30 upstream repositories.

## Evidence hierarchy

Read claims in this order; a lower tier must not be promoted into a higher one.

| Tier | Artifact | Supported interpretation |
| ---: | --- | --- |
| 1 | [`artifacts/resilient-matrix.json`](../artifacts/resilient-matrix.json) | Direct isolated-staging mutation, authorized materialization, real visible/invariant execution, non-release recovery and hashes on authored repository fixtures |
| 2 | [`artifacts/quorum-model.json`](../artifacts/quorum-model.json) | Exhaustive decisions inside a finite declared message model |
| 3 | [`artifacts/faultbench-results.json`](../artifacts/faultbench-results.json) | Protocol-message comparison on 30 provenance-bound case identities |
| 4 | [`artifacts/faultbench-micro-replays.json`](../artifacts/faultbench-micro-replays.json) | Three real standalone semantic executions, one per language |
| 5 | [`artifacts/faultbench-source-verification.json`](../artifacts/faultbench-source-verification.json) | Read-only public metadata verification at retrieval time |
| 6 | [`artifacts/container-isolation.json`](../artifacts/container-isolation.json) | One passing local container boundary probe |
| 7 | `artifacts/agentteams-live-evidence.json` | Conditional official v1.2.2 live evidence; counts only when strict validation succeeds |
| 8 | Four post-HEAD receipts inside the public v0.2.0 release ZIP, with clean replay traced to the exact public CI artifact | Frozen-commit replay, public-CI, evidence-manifest, and champion-gate authority only when every strict validator passes; missing means pending |
| 9 | Video, PDF, dashboard, YAML | Explanation or deployment design; not a substitute for runtime receipts |

## Raw evidence index

### Champion mechanism

- [`artifacts/resilient-matrix.json`](../artifacts/resilient-matrix.json): 22
  complete trial records, raw proposals, ingress dispositions, actor registry,
  test receipts, attestations, quorum decision, reason codes, candidate/snapshot
  hashes, terminal state, per-trial digest, and full-matrix digest.
- [`artifacts/quorum-model.json`](../artifacts/quorum-model.json): state-space
  definition, assumptions, checked/authorized counts, six properties, and any
  counterexamples.
- [`docs/RESILIENT_RUNTIME.md`](RESILIENT_RUNTIME.md): executable protocol and
  exact claim boundary.
- [`docs/FAULT_TOLERANCE.md`](FAULT_TOLERANCE.md): identity, authority,
  evidence-binding, and quorum contract.

### Cross-repository anchors

- [`faultbench/cases.json`](../faultbench/cases.json): 30-case declared
  protocol-simulation corpus.
- [`artifacts/faultbench-results.json`](../artifacts/faultbench-results.json):
  120 case/profile gate decisions.
- [`artifacts/faultbench-source-verification.json`](../artifacts/faultbench-source-verification.json):
  30 passing public metadata validations.
- `artifacts/faultbench-source-verification.raw.json`: local-only retrieval payload, deliberately
  excluded from publication; its SHA-256 and all compared fields remain in the public summary.
- [`artifacts/faultbench-micro-replays.json`](../artifacts/faultbench-micro-replays.json):
  Python, JavaScript, and Rust execution records.
- [`docs/AGENTFAULTBENCH.md`](AGENTFAULTBENCH.md): dataset and replay boundary.

### Engineering boundary

- [`artifacts/container-isolation.json`](../artifacts/container-isolation.json):
  no-network, read-only-root, scrubbed-environment boundary probe.
- Frozen-release receipts: `clean-replay.json`, `public-ci.json`,
  `champion-evidence.json`, and `champion-gate.json` are intentionally generated
  after the frozen HEAD and are not source-tree authority. Inspect them inside
  the public v0.2.0 release ZIP, and trace the clean receipt to the exact public
  CI artifact for that HEAD. Missing carrier, missing receipt, or failed strict
  validation means pending; no archive/test/final-package claim is made before
  then.
- [`artifacts/benchmark.json`](../artifacts/benchmark.json): eight authored
  incidents across full and ablated legacy profiles.
- [`docs/SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md): trust assumptions,
  covered faults, exclusions, and production hardening.
- [`docs/DISCLOSURE.md`](DISCLOSURE.md): models, APIs, data, cost, tools, licenses,
  and readiness status.

## AgentTeams evidence status

The repository contains official-shape AgentTeams manifests and a reusable
Skill. Count the official live result only when
`artifacts/agentteams-live-evidence.json` exists and passes strict validation.
A valid receipt binds official v1.2.2 Controller + Manager + eight Worker
containers, an adapter-assisted/operator-captured Matrix typed protocol, two
real proposer Skill executions, two Verifiers, lead reviewer, Challenger,
Governor, actual Release Manager `QuorumGate`, Manager relay, and ACL evidence.
It binds local `gpt-oss:20b` (20.9B, MXFP4, Apache-2.0, digest beginning
`17052f91`, USD 0 model/API fees, local compute) and only an adapter-executed
Alibaba Skill missing-credential preflight with no cloud query. It does not
claim LLM-autonomous orchestration. If the strict artifact is absent or invalid,
the older blocked attempt remains historical diagnostics and none of these
successful-loop statements count.

## What would falsify the main claim

Reject the champion mechanism result if any rerun shows:

- a one-Worker fault authorizing a non-oracle patch;
- single-Worker recovery below 90% of the no-fault baseline;
- an enumerated overflow/control-failure trial retaining modified bytes;
- a release without two distinct Worker proposals, two Verifier approvals,
  Challenger approval, Governor approval, and a registered Release Manager;
- mismatched run, candidate, or snapshot context being accepted; or
- a matrix digest that no longer matches its content.

These are machine-checked gates, not presentation preferences.

## Claims judges should not infer

- “Byzantine fault tolerant” without the words *bounded one-Worker model*;
- “22 real-world repositories repaired”—the 22 trials use fresh authored
  repository fixtures;
- “30 upstream bugs reproduced”—the 30 cases are protocol simulations;
- “three upstream projects fully replayed”—only three extracted semantics ran;
- “production sandbox” from one Docker boundary probe; or
- “official AgentTeams run” from manifests alone.

## Current readiness boundary

This guide verifies the deterministic mechanism; it does not declare the whole
submission final-ready. The strict AgentTeams receipt and delivery bytes must be
frozen first. The authoritative machine champion gate is then the post-HEAD copy
inside the public v0.2.0 release ZIP, validated together with its manifest,
public-CI receipt, and clean receipt from the exact CI artifact. Until that
public proof exists, readiness is pending.
