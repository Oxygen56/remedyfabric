# Security threat model and claim boundary

## Security objective

RemedyFabric protects a repository from an autonomous repair control plane that
may itself be partially faulty. Its primary invariant is:

> No single registered repair Worker can independently cause release; the
> governed workspace receives no candidate write before Governor-backed quorum
> authorization; and every non-release terminal path retains or restores the
> captured pre-change bytes.

The reference implementation prefers a visible denial over a weakly evidenced
release. Liveness is measured only inside the declared one-Worker boundary.

## Protected assets

- source files and the exact pre-incident workspace state;
- tests, invariants, CI/deployment configuration, repository metadata, license,
  dependency manifest, and environment files;
- credentials and host environment values;
- the identity, role, run, snapshot, candidate, and evidence context used for a
  release decision; and
- audit receipts needed to explain why a patch was released or rolled back.

## Actors and authority

| Role | Granted authority | Explicitly denied authority |
| --- | --- | --- |
| Worker | Produce a typed `PatchCandidate` under its own registered identity against the supplied snapshot | Verify, govern, challenge, request release, or count twice |
| Verifier | Execute visible/invariant tests and bind the result to one candidate/context | Propose, modify, govern, or release a patch |
| Challenger | Search for counterexamples and verify patch materialization/invariants | Replace a missing Worker, Verifier, Governor, or Release Manager |
| Governor | Apply path, secret, scope, protected-file, and edit-size policy | Generate a patch or substitute for test evidence |
| Release Manager | Ask the deterministic gate to evaluate the collected artifacts | Override a missing quorum, rejection, conflict, or invalid binding |

Actor IDs are unique and preregistered with exactly one role. Duplicate messages
from one identity do not increase quorum. A claimed role that disagrees with the
registry is quarantined or ignored with a reason code.

## Trusted computing base

The bounded claim assumes:

- membership and one-role-per-actor registration are correctly provisioned;
- runtime identity prevents an actor from stealing another registered identity;
- at most one of three repair Workers is Byzantine-like inside the liveness claim;
- the two Verifier identities, Challenger, Governor, and Release Manager remain
  uncompromised for the covered one-Worker result; these logical roles share one
  Python implementation/provider and are not independent fault domains;
- the Python process, hash function, filesystem, kernel, and clock/timeout
  mechanism behave as observed; and
- visible and invariant tests encode the behavior the evaluator intends to
  preserve.

SHA-256 binds evidence content to run, candidate, and pre-change snapshot. It
detects content/context tampering in the reference protocol, but it is not an
actor signature, workload identity, external timestamp, or transparency log.

## Faults covered by the executable one-Worker matrix

One preregistered Worker may exhibit one of eight injected behaviors:

1. **crash:** emits no proposal;
2. **equivocation:** emits different patch digests for the same run;
3. **forged proposal:** claimed patch digest does not match executable content;
4. **replay:** proposal is bound to a prior run;
5. **unsafe patch:** proposal overfits the visible test and breaks an invariant;
6. **context mismatch:** proposal is bound to another snapshot;
7. **role impersonation:** Worker claims Release Manager authority; or
8. **timeout:** proposal misses a real deadline.

In the retained 22-trial matrix, all eight single-Worker trials recover the safe
candidate, yield zero unsafe releases, and preserve 100% of no-fault recovery.
The validator never receives the fault label; it evaluates identity, integrity,
context, convergence, and evidence.

## Release invariant

Release requires:

```text
2 distinct Worker proposals for the same executable patch
+ 2 distinct Verifier approvals
+ 1 Challenger approval
+ 1 Governor approval
+ 1 request by the registered Release Manager
+ every artifact bound to the same run, patch, and snapshot
= release

anything else = rollback
```

Configuration enforces `proposal_quorum > max_faulty_workers`. A patch is first
applied as a reversible transaction in a symlink-preserving disposable staging
copy so separate tests execute against real candidate bytes without touching
the governed workspace. Only a Governor-backed quorum can authorize
materialization into that workspace, followed by a second verification pass.

## Tested overflow and control-plane failures

Thirteen deliberately out-of-boundary or control-failure trials exercise:

- two Worker crashes;
- two Worker timeouts;
- two colluding unsafe Workers whose patch reaches proposal quorum;
- two colluding traversal Workers;
- two colluding symlink-path Workers;
- two equivocating Workers;
- forged Verifier evidence;
- replayed Verifier evidence;
- Verifier evidence bound to another snapshot;
- Release Manager role impersonation;
- a timed-out Verifier;
- a missing Challenger; and
- a missing Governor.

Each bullet is one complete trial, producing thirteen total cases. All thirteen
retained decisions fail closed and verify byte-exact rollback or an untouched
baseline; the traversal and symlink trials also verify that an external byte
sentinel is unchanged. This
demonstrates those enumerated cases only. In particular, the system makes no
general guarantee against two colluding Workers that produce an unsafe patch
capable of satisfying all available tests and policy checks.

## Additional finite-model properties

The small-model checker exhaustively evaluated 20,748 decisions under its
published state space and found zero counterexamples for:

- single-Worker authorization;
- Worker release requests;
- rejection override;
- Worker equivocation authorization;
- control equivocation authorization; and
- forged/replayed evidence authorization.

This result is exhaustive for that model, not a mechanized proof about arbitrary
network sizes, scheduling, cryptography, processes, or repositories.

## Execution boundary

The reference executor accepts a fixed `python3 -m unittest` command family,
avoids a shell, scrubs the environment, and applies a timeout. The recorded
container probe additionally used:

- network disabled;
- read-only root filesystem and workspace;
- all Linux capabilities dropped;
- `no-new-privileges`;
- process, memory, and CPU limits; and
- a small `noexec`, `nosuid`, `nodev` temporary filesystem.

The probe denied network access, root-filesystem writes, and host secret/token
environment access. This was one local Docker execution. Python tests still
contain arbitrary code, Docker is not treated as a complete adversarial sandbox,
and none of these controls is claimed as a production deployment.

## Concurrency and TOCTOU boundary

The path, symlink and stale-content checks are exercised against a static
workspace controlled by the trial. They do not prove resistance to another
local process replacing a directory or file between validation and an atomic
rename. That authorization-window TOCTOU case is outside the retained claim.
Production adaptation must isolate or lock the workspace and use directory-file
descriptors with `openat2`-style no-symlink/beneath constraints (or an equivalent
platform mechanism) rather than relying only on path rechecks.

## Data and credential boundary

- The champion core needs no credentials, model, API, private dataset, or
  network access.
- Host environment values are not passed to the sandbox except a minimal
  allowlist needed for execution.
- The secret regex and protected-path rules are guardrails, not a complete DLP
  or information-flow system.
- Public GitHub API use is read-only and limited to metadata verification;
  authorization headers/tokens are not retained.
- The optional Alibaba Cloud Skill is pinned and package-verified. A valid
  strict live receipt may establish only an adapter-executed missing-credential
  preflight that stops before any cloud request; no cloud API was called, no
  resource data was retrieved, and no credential is embedded.

## Explicit exclusions

RemedyFabric does not claim protection from:

- compromise of the role registry, Release Manager, complete control plane, host
  OS/kernel, Python runtime, or hash implementation;
- stolen credentials or successful identity impersonation below the registry;
- arbitrary two-or-more-Worker collusion outside the exact tested cases;
- a malicious patch that satisfies every visible/invariant test and policy;
- another local process racing path or file replacement during validation or
  authorized materialization (TOCTOU);
- poisoned, incomplete, correlated, or adversarial tests/invariants;
- side channels, covert channels, denial of service, resource-exhaustion attacks
  outside configured limits, or distributed-network partition semantics;
- cryptographic consensus, external receipt timestamping, or non-repudiation;
- universal repair correctness, production incident coverage, or zero-day
  containment; or
- production safety certification.

Accordingly, “bounded faulty-Worker-resistant recovery” is accurate. “General
BFT,” “formally verified production safety,” and “unconditionally secure
autonomous repair” are not.

## Failure and recovery behavior

| Observed condition | Terminal behavior |
| --- | --- |
| No unique Worker patch quorum | Refuse candidate; restore snapshot |
| Malformed, forged, stale, replayed, or role-invalid proposal | Quarantine actor message; continue only if the required distinct-identity quorum remains |
| Worker equivocation | Quarantine that Worker's proposals; continue only if the required distinct-identity quorum remains |
| Absolute/traversal/symlink/duplicate/stale edit set | Reject the complete candidate before any target write |
| Staging apply or I/O failure | Refuse release; governed workspace remains untouched |
| Authorized materialization failure | Restore every captured original byte and verify the snapshot digest |
| Any staging visible/invariant failure | Verifier rejection; governed baseline remains untouched |
| Challenger counterexample or patch mismatch | Challenger rejection; governed baseline remains untouched |
| Governor policy denial | Governor rejection; governed baseline remains untouched |
| Missing, conflicting, forged, replayed, or context-mismatched control evidence | Quorum denial; governed baseline remains untouched |
| Unauthorized release requester | Quorum denial; governed baseline remains untouched |
| All required role gates approve the same bound context | Retain patch and issue release receipt |

Every rollback path compares the final workspace digest with the original
snapshot digest. A rollback claim without digest equality is a failed trial.
Snapshot capture includes paths named `evidence` and rejects symlinks rather
than following them. Candidate application validates the full multi-edit set
before creating targets and rolls back earlier replacements if a later atomic
replacement fails.
The snapshot covers ordinary workspace files other than `.git`; `.git` is
excluded from byte restoration and separately denied as a candidate edit root.

## Production hardening required

Before adapting the reference core to real customer repositories:

1. run each role and test workload in separately authenticated ephemeral
   microVMs or hardened containers;
2. enforce signed workload identity, mutually authenticated channels, short-lived
   scoped credentials, and role ACLs outside Python data structures;
3. use signed images, locked dependencies, SBOM/provenance verification,
   seccomp/AppArmor/SELinux, egress policy, quotas, and immutable audit storage;
4. sign and externally timestamp proposals, evidence, decisions, and rollback
   receipts;
5. use independent and adversarial test generation, fuzzing, static analysis,
   secret scanning, and human approval for deployment/data/permission changes;
6. validate rollback for databases, queues, external APIs, and deployment state,
   not only repository bytes; and
7. monitor drift in policy, runtime, models, tools, test quality, fault rates, and
   recovery outcomes with an explicit kill switch.
8. eliminate authorization-window path races with exclusive workspace isolation
   or locking plus directory-descriptor-based, no-follow, beneath-only file APIs.

See [`docs/DISCLOSURE.md`](DISCLOSURE.md) for the model/API/data/tool ledger and
[`docs/JUDGE_GUIDE.md`](JUDGE_GUIDE.md) for exact evidence inspection.
