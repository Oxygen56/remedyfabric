# Clean Release Replay

`scripts/run_clean_replay.py` builds both release archives, records their SHA-256 digests,
rejects traversal, symlink and archive-integrity failures, builds with `uv --offline`, installs
only the local wheel into a fresh pinned Linux image, and runs the full unit suite plus
RemedyBench. The container image build and runtime both have networking disabled.

The container also uses a read-only root filesystem, no Linux capabilities, no privilege
escalation, and explicit process, memory and CPU limits. The command stages its receipt at
`artifacts/clean-replay.json`.

## HEAD-bound authority

The v0.2.0 clean receipt cannot be final source-HEAD evidence: it is generated
only after that HEAD exists and binds the resulting source and archive bytes.
`clean-replay.json`, `public-ci.json`, `champion-evidence.json`, and
`champion-gate.json` are therefore intentionally post-HEAD, ignored working
files. Committing a generated copy and moving HEAD would invalidate the commit
binding it is meant to certify.

For the final release, the authoritative clean receipt must originate from the
exact frozen-HEAD public CI artifact and an identical validated copy must appear
inside the public v0.2.0 release ZIP alongside the other three post-HEAD
receipts. A same-named local file, an earlier receipt, or a repository link is
not authority. Until the public CI artifact and release ZIP exist and all four
receipts pass their strict validators, clean replay and champion readiness are
**pending**.

This is evidence for one clean replay on the recorded container architecture. It is not a claim
of reproducibility on every operating system, hardware platform, or production environment.
