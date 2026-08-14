#!/usr/bin/env python3
"""Render the evidence-bound, self-contained judge dashboard."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
from typing import Any

from remedyfabric.delivery_validation import (
    build_presentation_contract,
    require_presentation_render,
)

ROOT = Path(__file__).resolve().parents[1]


def _safe(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _percent(value: float | None) -> str:
    return "N/A" if value is None else f"{float(value):.0%}"


def _count(value: float | None) -> str:
    return "N/A" if value is None else f"{int(value):,}"


def _status(name: str, passed: bool, detail: str) -> tuple[str, bool, str]:
    return name, passed, detail


def render_dashboard(
    output: Path,
    *,
    allow_incomplete_preview: bool = False,
) -> dict[str, Any]:
    contract = build_presentation_contract(ROOT)
    require_presentation_render(
        ROOT,
        contract,
        [output],
        allow_incomplete_preview=allow_incomplete_preview,
    )
    status = contract["statuses"]
    metrics = contract["metrics"]
    topology = contract["topology"]
    digest = contract["presentation_contract_sha256"]
    complete = status["evidence_complete"]
    rows = [
        _status(
            "Fault-tolerant executable matrix",
            status["resilient"],
            f"{_count(metrics['trial_count'])} trials; byte/release terminal state revalidated",
        ),
        _status(
            "Finite exhaustive state exploration",
            status["model"],
            f"{_count(metrics['checked_decisions'])} decisions; general BFT explicitly out of scope",
        ),
        _status(
            "AgentFaultBench provenance",
            status["sources"] and status["faultbench"],
            (
                f"{_count(metrics['case_count'])} cases / "
                f"{_count(metrics['repository_count'])} repos / "
                f"{_count(metrics['language_count'])} languages / "
                f"{_count(metrics['fault_attack_count'])} faults"
            ),
        ),
        _status(
            "Executed semantic micro-replays",
            status["micro"],
            f"{_count(metrics['micro_fixture_count'])} independent Python, JavaScript and Rust fixtures",
        ),
        _status(
            "Container isolation probe",
            status["isolation"],
            "network none, read-only rootfs, dropped capabilities, resource bounds",
        ),
        _status(
            "Clean wheel replay",
            status["clean"],
            "isolated package replay passed"
            if status["clean"]
            else "not yet passed; excluded from completed claims",
        ),
        _status(
            "Official AgentTeams run",
            status["agentteams"],
            (
                f"validated live receipt; {topology['official_agentteams_worker_count']} distinct Worker containers"
                if status["agentteams"]
                else "pending final official runtime wiring - no completion claim"
            ),
        ),
    ]
    rows_html = "".join(
        f"<tr><td>{_safe(name)}</td><td><span class='pill {'ok' if passed else 'pending'}'>"
        f"{'VERIFIED' if passed else 'PENDING'}</span></td><td>{_safe(detail)}</td></tr>"
        for name, passed, detail in rows
    )
    commands_html = "".join(
        f"<li><code>{_safe(command)}</code></li>" for command in contract["commands"]
    )
    bound_evidence_html = (
        "".join(
            f"<li><code>{_safe(item['path'])}</code> <span class='digest'>{_safe(item['sha256'][:16])}...</span></li>"
            for item in contract["evidence_bindings"].values()
        )
        or "<li>No evidence file is currently valid enough to bind.</li>"
    )
    build_status = "PRE-FREEZE EVIDENCE SET COMPLETE" if complete else "EVIDENCE BUILD IN PROGRESS"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="remedyfabric:presentation-sha256" content="{digest}">
<title>RemedyFabric - GOAI Agent Infra Evidence Dashboard</title>
<style>
:root{{--bg:#07111f;--panel:#10213a;--line:#294766;--white:#eef5ff;--muted:#9eb2cf;--cyan:#43d9c4;--amber:#ffc857}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 90% 0,#183d65 0,transparent 34%),var(--bg);color:var(--white);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}main{{max-width:1240px;margin:auto;padding:52px 28px 80px}}
.eyebrow{{color:var(--cyan);font-weight:800;letter-spacing:.16em;font-size:13px}}h1{{font-size:64px;line-height:1;margin:18px 0}}h2{{font-size:28px;margin:54px 0 18px}}.lead{{font-size:23px;color:var(--muted);max-width:980px}}.status{{display:inline-block;margin-top:22px;padding:10px 16px;border:1px solid {"var(--cyan)" if complete else "var(--amber)"};color:{"var(--cyan)" if complete else "var(--amber)"};border-radius:999px;font-weight:800}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:40px 0}}.card{{background:rgba(16,33,58,.94);border:1px solid var(--line);border-radius:18px;padding:22px;min-height:148px}}.label{{font-size:12px;color:var(--muted);font-weight:800;letter-spacing:.08em;text-transform:uppercase}}.value{{font-size:42px;color:var(--cyan);font-weight:850;margin:12px 0 5px}}.sub{{color:var(--muted);font-size:14px}}
.thesis{{border-left:4px solid var(--cyan);padding:18px 24px;background:#0b192c;border-radius:0 14px 14px 0;font-size:21px}}table{{width:100%;border-collapse:collapse;background:var(--panel);border-radius:14px;overflow:hidden}}th,td{{text-align:left;padding:15px;border-bottom:1px solid var(--line)}}th{{font-size:12px;color:var(--muted);letter-spacing:.08em}}.pill{{display:inline-block;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:850}}.ok{{color:var(--cyan);background:#123b3a}}.pending{{color:var(--amber);background:#3b321b}}.two{{display:grid;grid-template-columns:1.2fr .8fr;gap:20px}}code{{color:var(--cyan);word-break:break-all}}.digest{{color:var(--muted)}}footer{{margin-top:58px;color:var(--muted);font-size:13px}}a{{color:var(--cyan)}}@media(max-width:800px){{h1{{font-size:44px}}.metrics,.two{{grid-template-columns:1fr}}}}
</style></head><body><main>
<div class="eyebrow">GOAI 2026 / AGENT INFRA / JUDGE EVIDENCE</div><h1>RemedyFabric</h1>
<p class="lead">Faulty-Agent-resistant recovery infrastructure: recovery stays safe when a Worker crashes, proposes unsafe output, equivocates, replays evidence, or crosses its role boundary.</p><span class="status">{build_status}</span>
<div class="metrics">
<section class="card"><div class="label">One-Worker recovery</div><div class="value">{_percent(metrics["faultbench_single_fault_recovery_rate"])}</div><div class="sub">{_count(metrics["faultbench_single_fault_cases"])} protocol-simulation cases within the declared Worker-fault boundary</div></section>
<section class="card"><div class="label">Unsafe release</div><div class="value">{_percent(metrics["faultbench_single_fault_unsafe_release_rate"])}</div><div class="sub">Modeled single-fault cases; not a production fault rate</div></section>
<section class="card"><div class="label">Overflow containment</div><div class="value">{_percent(metrics["faultbench_overflow_containment_rate"])}</div><div class="sub">{_count(metrics["faultbench_overflow_cases"])} overflow/control-plane cases fail closed</div></section>
<section class="card"><div class="label">State exploration</div><div class="value">{_count(metrics["checked_decisions"])}</div><div class="sub">Finite model, not a general BFT proof</div></section></div>
<p class="thesis"><b>Champion thesis:</b> {_count(topology["proposal_quorum"])} matching Worker proposals + {_count(topology["verifier_quorum"])} logically distinct Verifiers + Challenger + Governor + separate Release Manager. The evidence-derived local topology contains {_count(topology["recovery_role_counts"].get("worker"))} Workers and {_count(topology["recovery_role_counts"].get("verifier"))} Verifiers. Correlated implementation/provider failure is outside the claim. A single Worker never authorizes release.</p>
<h2>Evidence ledger</h2><table><thead><tr><th>Artifact</th><th>Status</th><th>What it proves - and no more</th></tr></thead><tbody>{rows_html}</tbody></table>
<h2>AgentFaultBench-OSS boundary</h2><div class="two"><section class="card"><p><b>Verified public provenance:</b> {_count(metrics["case_count"])} merged OSS PR identities span {_count(metrics["repository_count"])} repositories and {_count(metrics["language_count"])} languages.</p><p><b>Executed:</b> {_count(metrics["micro_fixture_count"])} extracted semantics in Python, JavaScript and Rust.</p><p><b>Not claimed:</b> the complete upstream repositories were not cloned, repaired, or run end-to-end. These are protocol-message evaluations, not {_count(metrics["case_count"])} autonomous OSS repairs or production reliability measurements.</p></section><section class="card"><div class="label">Evidence bindings</div><ul>{bound_evidence_html}</ul></section></div>
<h2>Evidence completeness before repository freeze</h2><section class="card"><div class="label">Pre-freeze evidence status</div><div class="value" style="font-size:30px;color:{"var(--cyan)" if complete else "var(--amber)"}">{"COMPLETE" if complete else "INCOMPLETE"}</div><p>This neutral status is recomputed from semantic validators and current file hashes. It never asserts final submission readiness. Public CI, final delivery QA, and the submission package are later post-HEAD gates.</p><p><code>presentation contract: {digest}</code></p></section>
<h2>Five-minute review path</h2><section class="card"><ol>{commands_html}</ol><p>Review <code>docs/DISCLOSURE.md</code> before enabling any external provider.</p><p>Public repository: <a href="https://github.com/Oxygen56/remedyfabric">github.com/Oxygen56/remedyfabric</a> - Apache-2.0</p></section>
<footer>Generated from machine-revalidated repository evidence. Coverage is not a predicted score, award guarantee, third-party certification, or production-safety claim.</footer>
</main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return {
        "output": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "size_bytes": output.stat().st_size,
        "official_agentteams_evidence": status["agentteams"],
        "pre_freeze_evidence_complete": complete,
        "presentation_contract_sha256": digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/dashboard.html"))
    parser.add_argument("--allow-incomplete-preview", action="store_true")
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    print(
        json.dumps(
            render_dashboard(
                output,
                allow_incomplete_preview=args.allow_incomplete_preview,
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
