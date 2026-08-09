# Model, API, Data and Tool Disclosure

Snapshot date: 2026-08-10.

| Item | Used in reproducible runtime? | Cost | License/terms | Reproduction impact |
| --- | --- | --- | --- | --- |
| Python 3.11+ standard library | Yes | Free | PSF License | Required; no third-party runtime package |
| RemedyBench-authored-v1 fixtures | Yes | Free | Apache-2.0 in this repository | Fully generated from published source |
| AgentTeams / HiClaw | Optional integration, not required for local benchmark | Software free; model/runtime infrastructure may cost money | Apache-2.0 upstream | Full deployment needs Docker/Kubernetes and an LLM provider; local role mapping reproduces without it |
| Alibaba Cloud Skills portal | Referenced integration path, not exercised in baseline | Product/API dependent | Alibaba Cloud product terms and each Skill's published license | Not needed for baseline; any live cloud proof must disclose account, region, API and spend |
| Codex | Used to assist project design, implementation, tests and documentation | User subscription/tooling cost not measured in benchmark | OpenAI service terms | Generated artifacts are committed and reviewable; runtime does not call Codex |
| Commercial model/API | No | USD 0.00 | Not applicable | Offline deterministic baseline remains reproducible |
| External/private dataset | No | USD 0.00 | Not applicable | No dataset download or account required |
| Pillow and imageio-ffmpeg | Demo-video build only; not runtime | Free | HPND and BSD-2-Clause; bundled FFmpeg under its reported build license | Needed only to regenerate MP4 frames and encode video |
| macOS `say` voice | Demo-video narration only | Free with local OS | Apple system software terms | Optional; video generator produces a silent MP4 when unavailable |

No benchmark score, test output, production adoption or external evaluation is claimed unless a corresponding artifact is linked. If the official submission form asks for AI assistance disclosure, the exact submitted wording must be reviewed before publication.
