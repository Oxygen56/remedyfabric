# Model, API, data, tool, cost, and license disclosure

Evidence snapshot: **2026-08-13**.

This ledger separates the zero-credential champion runtime from optional
deployment integrations and from tools used only to build or verify artifacts.
No paid model/API call is hidden inside the reported recovery metrics.

## Reproducible core

| Item | Used for reported core result? | Cost in retained run | License / terms | Reproduction impact |
| --- | --- | ---: | --- | --- |
| Python 3.11+ standard library | Yes | USD 0.00 | PSF License | Required for the resilient runtime, quorum checker, protocol evaluation, authored benchmark, and tests |
| RemedyFabric source | Yes | USD 0.00 | Apache-2.0 | Complete source, tests, scripts, docs, and retained JSON evidence are included |
| Authored temporary repository fixtures | Yes, for 22 executable resilience trials | USD 0.00 | Apache-2.0 as part of this repository | Created fresh for every trial; no external dataset or upstream checkout required |
| RemedyBench-authored-v1 | Secondary authored benchmark | USD 0.00 | Apache-2.0 as part of this repository | Eight transparent deterministic incidents; not asserted to represent production frequency |
| Commercial LLM/API | No | USD 0.00 | Not applicable | No model key, account, network request, or token spend is required for reported core metrics |
| Private/proprietary dataset | No | USD 0.00 | Not applicable | No customer code, private repository, personal data, or private benchmark is used |

The deterministic `RuleBasedRecoverySkill` is an evaluation provider behind the
same typed `PatchCandidate` interface that a model-backed provider would use.
Replacing it does not remove proposal quorum, policy, verification, challenge,
release authority, rollback, or evidence binding.

## AgentFaultBench-OSS data boundary

The 30 records in `faultbench/cases.json` contain public metadata for merged PRs
from Flask, Requests, Express, Fastify, ripgrep, and axum. Stored fields include
repository identity, PR and commit links, merge SHA/time, issue link where
present, repository SPDX license, and a case-specific synthetic protocol
transformation.

| Item | Actual use | Rights / license handling | Claim boundary |
| --- | --- | --- | --- |
| GitHub official REST API | Read-only revalidation of public PR, commit, issue, and repository-license metadata | Subject to GitHub API terms; authentication may be used only for rate limits, and tokens/headers are not retained | Confirms metadata at retrieval time; not bug reproducibility, intent, or patch correctness |
| 30 public defect-fix identities | Inputs to a synthetic protocol-simulation corpus | Links and facts are retained; upstream source is not copied into the corpus | Not 30 cloned, built, tested, or autonomously repaired repositories |
| Synthetic fault transformations | Produce concrete proposal/attestation faults | Authored in this repository under Apache-2.0 | No malicious or faulty behavior is attributed to upstream maintainers or contributors |
| Three semantic micro-replays | Independently authored standalone Python, JavaScript, and Rust fixtures | Fixture source is Apache-2.0 here; each provenance record links the upstream PR/diff and repository license | Executes one extracted observable semantic only; does not import or run the upstream project |

The source-verification receipts contain public API responses with authorization
headers and tokens omitted. Repository licenses represented in metadata include
BSD-3-Clause, Apache-2.0, MIT, and Unlicense. Those licenses govern their upstream
projects; RemedyFabric does not relicense or redistribute those projects.

## Optional runtime and ecosystem integrations

| Item | Status in retained champion evidence | Cost | License / terms | Reproduction impact |
| --- | --- | ---: | --- | --- |
| AgentTeams / HiClaw v1.2.2 | Conditional: only a strict-validator-passing live artifact establishes official Controller + Manager + 8 Worker containers, an adapter-assisted/operator-captured Matrix typed protocol, two real recovery-Skill proposer runs, two Verifiers, lead reviewer, Challenger, Governor, actual Release Manager `QuorumGate`, Manager relay, and ACL evidence | USD 0.00 in model/API fees; local compute | Official upstream is Apache-2.0 | Not required for deterministic metrics. This is operator-assisted evidence, not an LLM-autonomous-orchestration or independent-fault-domain claim |
| Local Ollama `gpt-oss:20b` | Conditional live provider, bound only by a valid strict receipt; digest `17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7`, 20.9B parameters, MXFP4 | USD 0.00 model/API fees; local compute only | Apache-2.0; weights are not redistributed here | Judges need the local model and official gateway for the optional live path, but not for the deterministic core. The model does not contribute to core metrics |
| Official Alibaba Cloud `alibabacloud-resourcecenter-search` Skill | Public package pinned and verified; conditional strict live evidence binds only an adapter-executed missing-credential preflight, with no credential read and no cloud request | USD 0.00 in the captured preflight; any real cloud resources would follow Alibaba Cloud billing | Alibaba Cloud terms and upstream package terms apply; package is not vendored | No account, region, resource result, cloud query, or billable action contributed to any result |
| Model-backed `PatchCandidate` provider | Supported extension point, not exercised | Provider-dependent | Provider terms apply | Must disclose model/version, endpoint, data policy, prompts, token use, cost, and reproducibility impact before any result is added |

Earlier unsuccessful diagnostics used local `qwen2.5:0.5b`, `qwen3:14b`, and
`qwen3-vl:2b`. They remain historical troubleshooting context only, are not the
final live provider, and contribute to no metric or successful-loop claim.

The Alibaba Cloud Skill is not redistributed because no repository-level
`LICENSE` or `NOTICE` was found at the pinned commit. The lock record preserves
the public source, commit, paths, and hashes without implying redistribution
rights. Cloud credentials are neither required nor present in the baseline.

## Evidence and development tools

| Tool | Purpose | Included in runtime metric? | Cost / license note |
| --- | --- | --- | --- |
| Docker with pinned Python image digest | One retained container boundary probe; also used by the pending frozen-HEAD clean-replay workflow | The boundary probe is current evidence; clean replay becomes final evidence only through the post-HEAD authority described below | Local compute; Docker and image terms apply. One architecture/run is not a universal sandbox or cross-platform proof |
| Python 3.13.14 | Captured Python micro-replay runtime | Yes, for one micro-replay only | PSF License |
| Node.js v26.4.0 | Captured JavaScript micro-replay runtime | Yes, for one micro-replay only | Node.js project licenses |
| Rust 1.96.0 | Compiled and ran the Rust micro-replay | Yes, for one micro-replay only | Rust toolchain licenses |
| `uv` | Package build / clean-replay tooling | No core runtime dependency | Tool license; local compute only |
| Ruff and Coverage | Optional lint/test tooling | No runtime dependency | Open-source tool licenses |
| Pillow and imageio-ffmpeg | Demo-video frame generation and encoding only | No | HPND and BSD-2-Clause; bundled FFmpeg reports its own build license |
| ReportLab, pypdf and pdfplumber | PDF generation plus structural/text/layout inspection | No | BSD, BSD-3-Clause and MIT; exact versions are pinned in `requirements/pdf.txt` |
| Poppins Regular and Bold | Embedded PDF font and rasterized video-frame font | No | SIL OFL 1.1; font files, hashes and full license are retained under `assets/fonts/Poppins/` |
| Final demo-video audio contract | Caption-first and silent; any provisional render containing an audio track is excluded from final evidence | No | Delivery validation must reject an MP4 with an audio stream; no narration or music is claimed |
| Codex | Assisted research, architecture, implementation, testing, documentation, and artifact preparation | Runtime does not call Codex | User subscription/tooling cost was not allocated to benchmark runs; OpenAI service terms apply |

[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) is the redistribution ledger for fonts,
document/video tooling, AgentTeams, GitHub metadata, and the referenced Alibaba Cloud Skill.

## Current evidence readiness disclosures

- [`artifacts/resilient-matrix.json`](../artifacts/resilient-matrix.json): passing,
  direct executable evidence.
- [`artifacts/quorum-model.json`](../artifacts/quorum-model.json): passing inside
  its finite declared model.
- [`artifacts/faultbench-results.json`](../artifacts/faultbench-results.json):
  protocol simulation, not upstream execution.
- [`artifacts/faultbench-micro-replays.json`](../artifacts/faultbench-micro-replays.json):
  three passing standalone semantic executions.
- [`artifacts/faultbench-source-verification.json`](../artifacts/faultbench-source-verification.json):
  public metadata verification only.
- [`artifacts/container-isolation.json`](../artifacts/container-isolation.json):
  passing for one local Docker boundary probe.
- `clean-replay.json`, `public-ci.json`, `champion-evidence.json`, and
  `champion-gate.json`: post-HEAD, self-referential release receipts. They are
  intentionally not source-tree authority. The final clean receipt must
  originate from the exact frozen-HEAD public CI artifact; all four authoritative
  copies must appear in the public v0.2.0 release ZIP and pass strict validation.
  If the CI artifact, release ZIP, or any receipt is missing, final readiness is
  pending. No current-source archive, test count, duration, or final-package
  replay is claimed beforehand.
- [`artifacts/agentteams-runtime-blocked.json`](../artifacts/agentteams-runtime-blocked.json):
  historical partial-runtime and ACL-denial evidence only; it never proves a
  successful loop. A later `artifacts/agentteams-live-evidence.json` supersedes
  that failure for final-live status only when it exists and strictly validates.
- `artifacts/agentteams-live-evidence.json`: conditional authority for the live
  claims above. If missing or invalid, the successful official loop, role-helper
  chain, provider binding, and Alibaba preflight are all not claimed.
- The champion gate inside that release ZIP: static documents, a same-named
  local file, video, PDF, dashboard, or an expected future artifact cannot
  override its strictly validated result.

## Costs reported by the project

The retained deterministic runtime, finite checker, protocol evaluation, and
semantic micro-replays report **USD 0.00 in model/API fees**. This number does not
pretend that developer hardware, electricity, internet access, user software
subscriptions, or labor are free. Protocol fields named `cost_proxy_units` and
`latency_proxy_ms` are deterministic comparison proxies, not observed dollars,
tokens, or wall-clock milliseconds.

Any future result that uses a commercial model, hosted API, paid cloud resource,
or restricted dataset must report provider, product/model version, region where
relevant, input/data policy, token or request count, measured cost, license/terms,
and whether a judge can reproduce the result without the same account.

## Intellectual property and redistribution

- RemedyFabric code, authored fixtures, docs, and project-owned artifacts are
  released under Apache-2.0.
- Public upstream projects retain their own licenses and trademarks.
- The protocol corpus stores links, identifiers, factual metadata, and authored
  synthetic transformations; it does not redistribute complete upstream code.
- The three semantic micro-replays are independently written and explicitly
  scoped to one observable semantic each.
- The official Alibaba Cloud Skill package is referenced and hashed, not
  vendored.
- No private source, credential, model weight, customer dataset, private personal data, or full
  GitHub user/API payload is included in the published repository or submission package. The
  local-only raw retrieval receipt is represented publicly by a SHA-256 and minimized comparisons.

## AI assistance disclosure

Codex was used extensively to assist project research, design, implementation,
tests, documentation, and evidence preparation. All submitted source and claims
must remain reviewable against committed artifacts; Codex is not part of the
offline runtime. If the competition form presents a dedicated AI-assistance
disclosure field, the exact form wording and final response must be reviewed
before submission rather than inferred from this document.

No benchmark score, live deployment, external adoption, public CI state, or
third-party evaluation is claimed without a corresponding retained receipt tied
to the submitted commit.
