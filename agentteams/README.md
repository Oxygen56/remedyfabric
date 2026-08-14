# AgentTeams Integration

`remedyfabric-team.yaml` uses the official `agentteams.io/v1beta1` Worker and Team CRDs. It defines
eight Worker identities: an orchestration-only leader, two distinct proposers, two distinct
verifiers, a Challenger, a Governor, and a separately authorized Release Manager. Together with
the official Controller and Manager, this is the live topology. The deterministic local runtime
remains the byte-exact transaction implementation and uses a three-Worker proposal topology.
These are separately registered and authorized roles, not a claim of independent model,
implementation, machine, or provider fault domains.

The portable manifest deliberately uses placeholder model IDs and no secrets. The local-live
manifest pins `gpt-oss:20b` through local Ollama: model digest
`17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7`, 20.9B parameters,
MXFP4 quantization, Apache-2.0, USD 0.00 model/API fees, and local compute. Before another live
deployment, use an authorized provider configured in AgentTeams and package the custom Skill under
the Manager's `worker-skills/remedyfabric-recovery/` directory. Credentials must be injected
through AgentTeams/Higress credential handling, never committed.

The portable manifest is a design skeleton, not an immediately deployable file. Replace every
`replace-with-authorized-model` value with an authorized provider model and configure its
credentials through AgentTeams before applying it. Then, after installing official AgentTeams:

```bash
hiclaw apply -f agentteams/remedyfabric-team.yaml
hiclaw get workers
hiclaw get teams
```

Live status, Matrix traces, role executions, and provider costs count only when
`artifacts/agentteams-live-evidence.json` exists and passes the strict validator. When valid, that
receipt represents an **adapter-assisted, operator-captured** Matrix typed protocol across official
AgentTeams v1.2.2 Controller, Manager, and all eight Worker containers: two real recovery-Skill
proposers; two Verifiers; lead reviewer; Challenger; Governor; and a Release Manager that actually
executes `QuorumGate`. It does not claim LLM-autonomous end-to-end orchestration or independent
model/provider/machine fault domains. If the artifact is absent or invalid, the complete live loop
is not claimed. A connectivity ping is never treated as the champion loop.

The official Alibaba Cloud discovery Skill is pinned and package-verified, but the live design
permits only an adapter-executed missing-credential preflight. No cloud query, credential read,
cloud result, or billable action is claimed. The deterministic local runtime is the zero-credential
reproducibility path.

Official upstream: <https://github.com/agentscope-ai/AgentTeams> (Apache-2.0).
