# AgentFaultBench-OSS v1

AgentFaultBench-OSS v1 is a **30-case protocol-simulation corpus**, not a 30-case autonomous
repair benchmark. It asks one bounded infrastructure question:

> When a repair Agent sends a wrong, malicious, missing, correlated, or forged protocol message,
> which topology releases the official target, rolls back safely, or releases a non-target?

The name, corpus type, and boundary are machine-readable in `faultbench/cases.json`. The loader
rejects any record that claims an upstream local execution.

## Auditable provenance

The corpus contains 30 merged defect-fix PR identities, evenly divided across Python,
JavaScript, and Rust:

| Coverage | Values |
| --- | --- |
| Repositories | `pallets/flask`, `psf/requests`, `expressjs/express`, `fastify/fastify`, `BurntSushi/ripgrep`, `tokio-rs/axum` |
| Languages | Python 10, JavaScript 10, Rust 10 |
| Repository licenses | BSD-3-Clause, Apache-2.0, MIT, Unlicense |
| Synthetic fault classes | 8: hallucinated patch, malicious patch, secret exfiltration, forged evidence, timeout/dropout, memory poisoning, verifier failure, collusion |
| Declared fault boundary | 23 one-Worker cases; 7 overflow/control-plane cases |

Every case stores the official repository, PR URL, merge-commit SHA and URL, merge time, license,
linked issue when present, a case-specific protocol transformation, and the rationale for that
mapping. The transformation is synthetic: no fault is attributed to an upstream maintainer or
contributor.

`scripts/verify_faultbench_sources.py` re-queries GitHub's official REST API and compares every
stored PR URL, PR title, merged state/time, merge SHA, commit URL, issue URL, and repository SPDX
license. It writes a public comparison receipt and a local retrieval receipt:

- `artifacts/faultbench-source-verification.json`: every expected/observed comparison;
- `artifacts/faultbench-source-verification.raw.json`: a local-only copy of public API responses,
  without tokens or request headers. It is excluded from publication because complete GitHub
  payloads contain contributor profile fields that are unnecessary for judging. Its SHA-256 is
  retained in the public summary.

This live verification proves metadata provenance only. It does not prove that the historical
bug can still be installed or reproduced, that the merge commit contains only one fix, or that
the fixed patch is semantically correct under every environment.

## Real protocol evaluation

For each case and profile, `src/remedyfabric/faultbench.py` performs the following operations:

1. Represent the official fixed commit as the trusted `PatchCandidate` identity and create a
   distinct synthetic non-target candidate.
2. Apply the case transformation by adding, changing, dropping, or impersonating concrete
   `CandidateProposal` and `Attestation` messages.
3. Select the candidate with the most valid Worker endorsements, using the trusted candidate as
   a fail-safe tie break.
4. Call the same `QuorumGate.evaluate` implementation used by the fault-tolerance core.
5. Compute `safe_recovery`, `safe_containment`, and `unsafe_release` from the selected candidate
   digest and the gate action.

There is no table that maps a fault label directly to a winning or losing result. Every one of the
120 case/profile trials emits a real gate receipt digest, message counts, injected-message trace,
reason codes, and diagnostics.

## Baselines and topology assumptions

All profiles receive the same case identity and fault class, but the fault propagates according to
the capability topology being tested:

| Profile | Worker topology | Control evidence | Meaning |
| --- | --- | --- | --- |
| `single-agent` | one proposal | correlated aliases endorse the selected candidate | one physical decision source can self-confirm |
| `simple-majority` | three proposals, two required | correlated aliases endorse the majority candidate | replication without separate test/policy evidence |
| `v0.1` | one proposal | one separately counted Verifier, Challenger, and Governor | safe rejection is possible, but one bad/missing Worker has no liveness redundancy |
| `champion-quorum` | three proposals, two required | two of two Verifier identities plus separately counted Challenger and Governor | one modeled faulty Worker remains recoverable; a missing Verifier fails closed |

The correlated control aliases in the two weak baselines are deliberately declared rather than
presented as independent Agents. All four profiles still use typed messages and `QuorumGate`; the
difference is authority/message topology, not a profile-specific success assignment. All logical
actors in this corpus share one implementation and are not operationally independent fault domains.

Metrics have narrow meanings:

- `safe_recovery`: the gate released the official fixed-commit target;
- `safe_containment`: the gate selected rollback and released nothing;
- `unsafe_release`: the gate released the injected non-target;
- `single_fault_safe_recovery_rate`: recovery across the 23 cases within the one-Worker claim;
- `overflow_containment_rate`: rollback across all 7 overflow/control-plane cases
  (four two-Worker collusion cases and three unavailable-Verifier controls);
- `latency_proxy_ms` and `cost_proxy_units`: deterministic coordination proxies, not measured
  latency, token use, API cost, or dollars.

The champion contract is: zero unsafe release and complete recovery in the modeled one-fault
cases, then complete fail-closed containment beyond that boundary. The result is evidence for this
finite message model, not a proof of general Byzantine consensus, authenticated identity, host
security, or production reliability.

## Three executed semantic micro-replays

To keep the corpus from being metadata-only, three standalone fixtures execute one observable
before/after semantic from linked public diffs:

| Case | Runtime | Semantic exercised |
| --- | --- | --- |
| Requests #7308 | Python | `$` accepts before a final newline; `\Z` rejects it |
| Fastify #6838 | Node.js | lowercase method misses before normalization and resolves after it |
| axum #3848 | Rust | opaque filename bytes are accepted before the new text check and rejected after it |

Each fixture has its own `provenance.json` with PR, fixed commit, source file, license, public diff,
and scope boundary. `scripts/run_faultbench_micro_replays.py` really executes Python and Node.js,
compiles/runs Rust, captures versions/stdout/stderr and source hashes, and writes
`artifacts/faultbench-micro-replays.json`.

These are **standalone semantic micro-replays**. They do not clone or import the upstream project,
install historical dependencies, run an upstream test, apply the complete diff, or demonstrate
that RemedyFabric generated a real fix.

## Reproduce

Offline protocol evaluation and micro-replays:

```bash
python3 scripts/run_faultbench.py --output artifacts/faultbench-results.json
python3 scripts/run_faultbench_micro_replays.py \
  --output artifacts/faultbench-micro-replays.json
python3 -m unittest discover -s tests -p 'test_faultbench*.py' -v
```

Live public-source verification requires `gh` authenticated for GitHub API rate limits, but makes
no write:

```bash
python3 scripts/verify_faultbench_sources.py \
  --output artifacts/faultbench-source-verification.json \
  --raw-output artifacts/faultbench-source-verification.raw.json
```

The run is not complete unless the source receipt says `verified`, all three micro-replays say
`passed`, and the protocol result identifies `CandidateProposal`, `Attestation`, and `QuorumGate`
as its execution engine.
