# Third-party notices

RemedyFabric source code is licensed under Apache-2.0. The following components are used to build,
verify, or render judge-facing artifacts unless stated otherwise. Generated PDFs, MP4s, and JPEGs
are project outputs; the notices below describe the tools and redistributed font files used to make
them. This ledger does not imply endorsement by any upstream project.

| Component | Purpose | License / terms | What is distributed here |
| --- | --- | --- | --- |
| Poppins Regular and Bold | Font embedded in the PDF and rasterized into video/preview pixels | SIL Open Font License 1.1; copyright 2020 The Poppins Project Authors | The two unmodified TTF files and complete `assets/fonts/Poppins/OFL.txt` |
| ReportLab 4.4.3 | PDF generation | BSD License | Dependency pin and generated PDF only; library code is not vendored |
| pypdf 6.0.0 | PDF structure and extracted-text verification | BSD-3-Clause | Dependency pin only; library code is not vendored |
| pdfplumber 0.11.7 | Optional PDF layout inspection | MIT | Dependency pin only; library code is not vendored |
| Pillow 11.3.0 | Raster video frames and contact sheet | HPND / MIT-CMU historical permission notice | Dependency pin and generated pixels only; library code is not vendored |
| imageio-ffmpeg 0.6.0 | Python wrapper for video encoding | BSD-2-Clause | Dependency pin only; wrapper code and binary are not vendored |
| FFmpeg 7.1 binary provided by imageio-ffmpeg | H.264 encoding and MP4 subtitle mux | GPL v2 or later for the bundled build; the build reports `--enable-gpl` and `--enable-libx264` | No FFmpeg binary or library is redistributed; only the generated MP4 is included |
| AgentTeams v1.2.2 | Official orchestration-runtime evidence | Apache-2.0 upstream | Manifests and minimized public evidence only; container images are not redistributed |
| Ollama 0.32.5 | Local model serving for the conditional official-live path | MIT, as reported by the installed official Homebrew formula | Used locally only; the Ollama binary and source are not redistributed |
| `gpt-oss:20b` (`17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7`) | Local model for the conditional official-live path | Apache-2.0, as reported by the installed model metadata | Used locally only; model files and weights are not redistributed |
| Alibaba Cloud AIOps Skill metadata | Optional ecosystem-integration evidence | Upstream terms; redistribution permission is not assumed | Lock metadata and hashes only; Skill source is not vendored |
| GitHub REST metadata | Public provenance validation | GitHub API terms | Minimized comparisons and retrieval hashes; full API payloads are not published |

## Redistributed Poppins files

The Poppins files were retrieved from the official Google Fonts `ofl/poppins/` source path. The
delivery validator rejects any substitution by checking these SHA-256 values:

- `Poppins-Regular.ttf`: `7e65201e9b79159e2300267cc885e16c8dcef2424cdfa09a29bfb0980a94a7ba`
- `Poppins-Bold.ttf`: `983676516167748b74de6f4771fb384c664fd913acb8b471122ecacf5da5ea6c`
- `OFL.txt`: `6be04893d770899a015649c7aa3b582f871b272f8747a92b78b17c3e5c8b2573`

The retained OFL permits use, embedding, and redistribution subject to its stated conditions. The
unmodified license text and copyright notice remain adjacent to the font files.

## Audio and voice boundary

The final demo generator does not call a speech synthesizer, does not use a macOS/Apple system
voice, and does not ship an audio stream. The MP4 is intentionally silent and caption-first: it
contains exactly one H.264 video stream and one complete English `mov_text` subtitle stream. The
delivery validator extracts the subtitle stream, compares all seven cues to the evidence-derived
caption contract, and rejects any audio stream. Therefore no voice recording or voice-model rights
are asserted or redistributed.

This notice is a practical redistribution ledger, not legal advice.
