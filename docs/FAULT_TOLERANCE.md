# Fault-tolerant recovery quorum

## Judge-facing claim

RemedyFabric's champion protocol makes one fact mechanically testable: **one repair
Worker cannot authorize its own patch**. A release needs convergent proposals from
two registered Workers, two distinct registered Verifier approvals, a Challenger approval,
a Governor approval, and a request from the separately registered Release Manager.
Every approval is bound to the same run, pre-change snapshot, executable patch, and
evidence artifact. Missing, stale, forged, replayed, rejecting, or contradictory
control evidence selects `rollback`, never an optimistic release.

This is a bounded, Byzantine-like recovery safety model. It is **not** a claim of a
general Byzantine fault-tolerant consensus protocol.

## Threat model

Within the claimed boundary, at most one pre-registered repair Worker may:

- crash or disappear;
- propose an arbitrary or unsafe typed `PatchCandidate`;
- submit the same proposal repeatedly;
- equivocate by proposing different patches for the same run;
- replay or fabricate evidence while using only its registered Worker identity.

The protocol also detects malformed, replayed, or conflicting artifacts from a
registered control actor and fails closed. Control roles may be unavailable; absent
votes cannot be replaced by Worker votes and therefore cause rollback.

The current implementation assumes that membership and role assignment are
provisioned by a trusted runtime, the control-plane roles remain uncompromised,
and actor identity is authenticated outside this pure-Python reference core. The
logical roles share one implementation/provider and are not independent failure
domains. SHA-256 binds artifacts to context and detects content tampering; it
does not authenticate people or processes by itself.

Out of scope are stolen control-plane credentials, collusion between enough Workers
to satisfy the proposal quorum, collusion or compromise across the Verifier,
Challenger, and Governor planes, SHA-256 compromise, host/kernel compromise, and
distributed-network consensus. Undetected collusion beyond the stated one-Worker
bound has no safety guarantee. Detectable overflow—missing quorum, equivocation,
conflict, evidence mismatch, or explicit rejection—always rolls back.

## Role and capability separation

| Role | May do | Cannot do |
| --- | --- | --- |
| Worker | Produce a typed patch proposal under its own registered identity | Verify, govern, challenge, or request release |
| Verifier | Bind visible/invariant test evidence to one patch | Propose a patch or release it |
| Challenger | Bind adversarial/negative-control evidence | Replace Verifier or Governor approval |
| Governor | Bind policy and permission evidence | Count as a Worker or Verifier |
| Release Manager | Ask the deterministic gate to evaluate | Override a missing or rejecting gate |

Actor IDs are unique and map to exactly one role. Duplicate proposals or votes do
not raise a count. A claimed role that differs from the membership registry is
ignored and reported as unauthorized.

## Safety decision

Default thresholds are:

```text
2 distinct Worker proposals for the same executable patch
+ 2 distinct Verifier approvals
+ 1 Challenger approval
+ 1 Governor approval
+ a registered Release Manager request
= release

anything else = rollback
```

`proposal_quorum` must be strictly greater than `max_faulty_workers`, so an unsafe
configuration such as one proposal with one tolerated faulty Worker is rejected at
construction. The digest used for proposal convergence covers paths, preconditions,
and new file content. Diagnosis wording, edit reasons, and confidence do not alter
the executable-patch identity, allowing separately registered agents to converge despite
different explanations.

## Evidence binding

Each control attestation contains:

- run ID;
- executable patch digest;
- byte-exact pre-change snapshot digest;
- evidence type (`test`, `challenge`, or `policy`);
- digest of the concrete test, attack, or policy artifact;
- verdict and registered actor/role.

The resulting decision is itself emitted as a machine-readable receipt with a
SHA-256 digest. Production integration should add runtime-issued signatures or
workload identity; the reference core intentionally does not pretend that a plain
hash is a signature.

## Exhaustive small-model check

Run:

```bash
python3 scripts/check_quorum_model.py > artifacts/quorum-model-check.json
```

The checker enumerates every state in a finite model with three Workers, two
Verifiers, one Challenger, one Governor, two candidate patches, and both a valid
Release Manager and an unauthorized Worker requester. The checker enumerates each
Worker as absent, safe, unsafe, or equivocating and each control actor as absent,
approving, or rejecting. It additionally injects forged and replayed evidence into
every control role. Enumeration is not evidence of operational fault-domain
independence.

The JSON output reports the exact number of decisions checked and counterexamples,
if any, for these properties:

1. fewer than two distinct Workers never authorize release;
2. a Worker cannot request release;
3. a valid control rejection cannot be outvoted;
4. Worker equivocation never authorizes release;
5. control-role equivocation never authorizes release; and
6. forged or replayed control evidence never authorizes release.

The retained run checks **20,748** decisions. This topology matches the
three-Worker/two-Verifier champion gate; it is separate from the official live
manifest's two proposer Worker roles.

This is exhaustive for the declared finite state space, not a proof about arbitrary
network sizes, cryptographic identity, runtime isolation, or real production fault
rates.
