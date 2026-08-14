# Faulty-worker-resistant recovery runtime

## What is real

`remedyfabric.resilient` executes a filesystem transaction rather than grading
fault labels. Every trial creates a fresh Python repository with a failing
visible contract and preserved non-empty invariants. Three registered Workers
diagnose the failure in separate workspace clones and separately emit typed
`PatchCandidate` objects. The runtime then:

1. validates actor role, proposal integrity, run ID, snapshot digest, and
   per-actor consistency without seeing the injected fault label;
2. selects a unique 2-of-3 patch quorum and applies it with
   `apply_candidate` only to a disposable staging copy;
3. runs the visible and invariant suites through two separately invoked
   `SandboxExecutor` instances against that isolated copy;
4. adds a separately registered invariant/materialization Challenger, a
   `RecoveryPolicy` Governor, and a distinct Release Manager;
5. binds every verdict to the run, pre-change snapshot, candidate, evidence
   kind, and artifact digest before `QuorumGate` evaluates release; and
6. writes the governed workspace only after the Governor-backed quorum releases
   the staged candidate, then reruns verification; every other terminal path
   retains or restores the exact bytes captured by `WorkspaceSnapshot` and
   verifies its digest.

The overfit fault is executable: it changes `mean(values)` to always return
zero. It passes the visible empty-input test but fails the separate non-empty
invariant. In the two-Worker collusion trial that unsafe patch reaches proposal
quorum and is materially applied and tested in the isolated staging copy; the control plane
rejects it before the governed workspace receives any candidate write.

## Preregistered matrix

The matrix contains 22 trials:

- one no-fault baseline;
- eight one-fault Worker trials: crash, equivocation, forged proposal, replay,
  unsafe patch, snapshot-context mismatch, role impersonation, and a real
  deadline timeout; and
- thirteen deliberately out-of-boundary trials: two Worker crashes, two Worker
  timeouts, two colluding unsafe Workers, two colluding traversal Workers, two
  colluding symlink-path Workers, two equivocating Workers, forged, replayed,
  or context-mismatched Verifier evidence, Release Manager role impersonation,
  a timed-out Verifier, a crashed Challenger, and a crashed Governor.

The generated JSON preserves each raw proposal, generic ingress disposition,
separate test result hashes, evidence bindings, presented attestations,
quorum counts, reason codes, decision receipt, patched/final snapshot hashes,
and a digest for every trial and the whole matrix.

Run it from the repository root:

```bash
PYTHONPATH=src python3 scripts/run_resilient_matrix.py \
  --output artifacts/resilient-matrix.json
```

The command exits non-zero unless all preregistered checks hold:

- no-fault recovery is 100%;
- one faulty Worker causes zero unsafe releases;
- one-fault Worker recovery is at least 90% of no-fault recovery;
- every enumerated out-of-boundary trial fails closed with verified byte-exact
  rollback or an untouched baseline;
- no trial writes the governed workspace before authorization or changes the
  external sentinel bytes; and
- every trial reaches either a released state or a verified rollback state.

## Claim boundary

The demonstrated guarantee is **one preregistered Byzantine-like Worker among
three** with a 2-of-3 proposal quorum, a trusted identity/role registry, two
distinct registered Verifier identities, one Challenger, one Governor, and a
separately authorized Release Manager. These logical actors share one Python
implementation/provider and are not independent fault domains. The matrix also
demonstrates fail-closed behavior for its explicitly
enumerated two-Worker and absent/tampered-control cases.

This is **not** general Byzantine fault-tolerant consensus, cryptographic actor
authentication, a proof against compromise or collusion of the complete control
plane, or a production safety proof. SHA-256 binds evidence content and context;
the deployment runtime must authenticate actor identity. The benchmark oracle
labels the intended safe patch so evaluation can count an alternative release
as unsafe even when a narrow test happens to pass.

## Workspace transaction safety

Before creating a directory, temporary file, or target write, `apply_candidate`
validates the complete edit set. Absolute paths, traversal, symlinked path
segments, duplicate normalized paths, non-files, undecodable old content, and
any stale old-content precondition reject the whole candidate with zero target
writes. Candidate replacements are staged and use atomic rename. If a later
replacement fails, earlier replacements are restored to their original bytes,
new targets are removed, and transaction-created directories are removed when
empty.

`WorkspaceSnapshot` walks without following links, includes ordinary paths
named `evidence` such as `src/evidence/module.py`, and refuses symlinks or
special files. The executable matrix additionally binds the preauthorization
workspace digest and an external sentinel digest into every trial receipt.

These checks are demonstrated on static trial workspaces. They do not claim to
prevent another local process from replacing a path between validation and
authorized rename; production adaptation needs workspace isolation/locking and
directory-descriptor-based beneath/no-follow operations.
