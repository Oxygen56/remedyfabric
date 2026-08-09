# AgentTeams Integration

`remedyfabric-team.yaml` uses the official `agentteams.io/v1beta1` Worker and Team CRDs. It defines a Team Leader plus four specialized Workers that mirror the local deterministic runtime.

The manifest deliberately uses placeholder model IDs and no secrets. Before a live deployment, replace `model` with an authorized provider configured in AgentTeams and package the custom Skill under the Manager's `worker-skills/remedyfabric-recovery/` directory. Credentials must be injected through AgentTeams/Higress credential handling, never committed.

Example after installing official AgentTeams:

```bash
hiclaw apply -f agentteams/remedyfabric-team.yaml
hiclaw get workers
hiclaw get teams
```

Live status, Matrix traces and provider costs are not claimed until those commands and an end-to-end team incident have been captured. The local runtime is the zero-credential reproducibility path.

Official upstream: <https://github.com/agentscope-ai/AgentTeams> (Apache-2.0).

