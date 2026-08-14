# Security Model

## Protected assets

- repository source and tests;
- CI and deployment configuration;
- credentials and environment variables;
- evidence integrity;
- pre-incident workspace state.

## Trust boundaries

Repair proposals are untrusted. The Governor rejects test, invariant, workflow,
repository metadata, dependency, license, environment, path escape, secret-like,
excessive-file and oversized edits. The executor has a fixed `python3 -m unittest`
command family, no shell, a scrubbed environment and a timeout. In the champion
protocol, candidate bytes are tested only in an isolated staging copy before the
Governor-backed quorum; the governed workspace is written only after authorization.
Denied trials retain the baseline, while a failed authorized materialization or
post-verification restores the captured bytes. Logical roles share one
implementation/provider and are not independent failure domains.

## Residual risks

- Python tests can execute arbitrary code present in an untrusted repository; production use requires an OS/container sandbox with network and filesystem isolation.
- Regex secret detection is a guardrail, not a complete DLP system.
- Authored fixtures are not representative of all languages or incident classes.
- Hash chains reveal tampering but do not provide an external timestamp or signer identity.
- A compromised host can tamper with code before the run; production should sign releases and receipts.
- The tested path and stale checks assume a static workspace; another local
  process racing directory/file replacement during authorization is outside the
  claim and requires locking/isolation plus descriptor-based no-follow operations.

## Production hardening plan

Run each incident in an ephemeral container or microVM, mount only the target workspace, disable network by default, apply CPU/memory/pid/time limits, use short-lived scoped credentials, sign receipts, integrate secret scanning and SBOM generation, and require human approval for deployment or data changes.

Report vulnerabilities privately to the repository owner until a public security channel is published. Do not include secrets or customer data in a report.
