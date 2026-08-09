# Security Model

## Protected assets

- repository source and tests;
- CI and deployment configuration;
- credentials and environment variables;
- evidence integrity;
- pre-incident workspace state.

## Trust boundaries

Repair proposals are untrusted. The Governor rejects test, invariant, workflow, repository metadata, dependency, license, environment, path escape, secret-like, excessive-file and oversized edits. The demo executor has a fixed unittest command family, no shell, scrubbed environment and a timeout. The Verifier runs independent invariants. Failed verification causes byte-exact restoration.

## Residual risks

- Python tests can execute arbitrary code present in an untrusted repository; production use requires an OS/container sandbox with network and filesystem isolation.
- Regex secret detection is a guardrail, not a complete DLP system.
- Authored fixtures are not representative of all languages or incident classes.
- Hash chains reveal tampering but do not provide an external timestamp or signer identity.
- A compromised host can tamper with code before the run; production should sign releases and receipts.

## Production hardening plan

Run each incident in an ephemeral container or microVM, mount only the target workspace, disable network by default, apply CPU/memory/pid/time limits, use short-lived scoped credentials, sign receipts, integrate secret scanning and SBOM generation, and require human approval for deployment or data changes.

Report vulnerabilities privately to the repository owner until a public security channel is published. Do not include secrets or customer data in a report.

