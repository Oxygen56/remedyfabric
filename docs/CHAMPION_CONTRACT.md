# RemedyFabric Champion Contract

## Winning claim

RemedyFabric is a recovery control plane that remains safe in its published
one-faulty-Worker model. When one of three registered Worker identities exhibits
an enumerated fault, no unsafe patch is released and honest proposals retain
liveness. When one of the 13 tested overflow/control cases occurs, it must refuse
release and retain or restore the captured pre-incident bytes.

This is deliberately narrower and more falsifiable than “safe autonomous repair.” It does not
claim a general asynchronous Byzantine consensus protocol or production reliability.

## What makes the claim memorable

Most recovery systems assume their repair and verification Agents are honest
enough. RemedyFabric tests failures in those logical actors. Role-separated
proposals, an adversarial Challenger, verification, evidence binding and a
deterministic release quorum turn an Agent team into a controlled recovery
experiment. The local actors share one implementation/provider and are not
presented as independent failure domains.

## Non-negotiable gates

The machine-readable contract is `competition/champion-contract.json`; `scripts/champion_gate.py`
is the fail-closed checker. A second GOAI submission is forbidden until the checker returns
`ready` on a frozen evidence manifest.

The required evidence includes:

1. zero unsafe releases across all eight published single-Worker fault modes;
2. at least 90% of fault-free recovery capability with one faulty Worker;
3. 100% fail-closed behavior across all 13 enumerated overflow/control trials;
4. zero governed-workspace writes before Governor-backed quorum authorization
   and zero external-sentinel byte changes across the 22-trial matrix;
5. exhaustive checking that no single Worker can authorize release;
6. 30 provenance-bound historical OSS identities across six repositories and
   three languages, explicitly scoped to protocol simulation;
7. a strict validated official AgentTeams v1.2.2 trace across Controller,
   Manager, and eight Worker containers, with an adapter-assisted/operator-captured
   Matrix typed protocol, two real proposer Skill executions, two Verifiers,
   lead reviewer, Challenger, Governor, an actual Release Manager `QuorumGate`
   decision, Manager relay, and runtime ACL evidence; this is not an LLM-autonomy claim; and
8. frozen 0.2.0 clean replay, package integrity, matching public CI, dashboard,
   PDF, silent video, disclosure, and final artifact hashes.

## Stop and rollback rules

- If evidence does not meet a threshold, the gate stays closed; wording is narrowed rather than
  metrics being hidden or redefined.
- The current successful initial submission remains the fallback.
- The second submission is the frozen champion build. The third opportunity is reserved only for
  a fatal packaging, link, rule or disclosure correction.

## Current status

The 22-trial deterministic mechanism gate passes. The official live gate passes
only if the strict AgentTeams artifact exists and validates; otherwise its
success remains unclaimed. The frozen-source 0.2.0 clean replay, final CI, and
delivery hashes are still pending until regenerated after source freeze. No
document or presentation may label the build final before the machine gate
changes to `ready` from validated artifacts.
