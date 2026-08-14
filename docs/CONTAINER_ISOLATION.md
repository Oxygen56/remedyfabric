# Container verification boundary

RemedyFabric can execute verifier tests in a Docker container with networking disabled, a
read-only root filesystem, an ephemeral image containing a read-only workspace, all Linux capabilities dropped,
`no-new-privileges`, a bounded process count, memory/CPU limits and a small no-exec `/tmp`.

Run the retained boundary probe:

```bash
.venv/bin/python3 scripts/run_container_isolation.py
```

The probe attempts a network connection, a root-filesystem write and access to host secret/token
environment keys. All three must be unavailable before the result is marked as passed.

This is evidence for one local Docker configuration. It is not a claim that Docker alone is a
complete hostile-code sandbox or that the same controls are active in production. A production
deployment should add an ephemeral VM/microVM boundary, seccomp/AppArmor policy, image signing,
SBOM verification and externally managed short-lived credentials.
