from __future__ import annotations

import html
import json
from pathlib import Path


def render_dashboard(benchmark_path: Path, output: Path) -> None:
    data = json.loads(benchmark_path.read_text(encoding="utf-8"))
    profiles = data["profiles"]
    full = next(item for item in profiles if item["profile"] == "full")
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(p['profile'])}</td>"
        f"<td>{p['task_success_rate']:.1%}</td>"
        f"<td>{p['recovery_success_rate']:.1%}</td>"
        f"<td>{p['safety_violation_rate']:.1%}</td>"
        f"<td>{p['rollback_success_rate']:.1%}</td>"
        f"<td>{p['ledger_integrity_rate']:.1%}</td>"
        "</tr>"
        for p in profiles
    )
    scenario_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(r['scenario_id'])}</td>"
        f"<td>{html.escape(r['expected_outcome'])}</td>"
        f"<td><span class='pill {r['outcome']}'>{html.escape(r['outcome'])}</span></td>"
        f"<td>{'✓' if r['task_success'] else '✗'}</td>"
        f"<td>{r['duration_ms']:.0f} ms</td>"
        "</tr>"
        for r in full["runs"]
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RemedyFabric Evidence Dashboard</title>
<style>
:root{{--ink:#eaf1ff;--muted:#9aacca;--bg:#08111f;--panel:#101d31;--line:#27405e;--cyan:#43d9c4;--amber:#ffc857;--red:#ff6b7a}}
*{{box-sizing:border-box}}body{{margin:0;font:16px/1.55 Inter,ui-sans-serif,system-ui;background:radial-gradient(circle at 80% 0,#16365b 0,transparent 38%),var(--bg);color:var(--ink)}}
main{{max-width:1180px;margin:auto;padding:48px 28px 80px}}h1{{font-size:48px;line-height:1;margin:0 0 12px}}h2{{margin-top:44px}}.tag{{color:var(--cyan);letter-spacing:.16em;text-transform:uppercase;font-weight:700}}.sub{{color:var(--muted);max-width:820px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:30px 0}}.card{{background:linear-gradient(155deg,#162844,#0d192b);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 16px 50px #0005}}.card b{{display:block;font-size:34px;color:var(--cyan)}}.card span{{color:var(--muted)}}
.flow{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.agent{{border:1px solid var(--line);background:#0d192b;padding:18px;border-radius:14px}}.agent strong{{color:var(--amber)}}
table{{width:100%;border-collapse:collapse;background:#0d192bcc;border:1px solid var(--line);border-radius:16px;overflow:hidden}}th,td{{padding:13px 15px;border-bottom:1px solid #20354f;text-align:left}}th{{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em}}.pill{{padding:4px 9px;border-radius:99px;background:#253c5b}}.recovered{{color:var(--cyan)}}.blocked,.rolled_back{{color:var(--amber)}}.failed{{color:var(--red)}}code{{color:var(--cyan)}}
@media(max-width:800px){{.cards,.flow{{grid-template-columns:1fr 1fr}}h1{{font-size:38px}}}}@media(max-width:520px){{.cards,.flow{{grid-template-columns:1fr}}}}
</style></head><body><main>
<div class="tag">GOAI 2026 · Agent Infra</div><h1>RemedyFabric</h1>
<p class="sub">A multi-agent recovery fabric that treats every autonomous repair as a controlled transaction: diagnose, propose, govern, verify, and either commit or roll back with a hash-chained receipt.</p>
<section class="cards"><div class="card"><b>{full["task_success_rate"]:.0%}</b><span>task success</span></div><div class="card"><b>{full["recovery_success_rate"]:.0%}</b><span>recoverable incidents fixed</span></div><div class="card"><b>{full["safety_violation_rate"]:.0%}</b><span>safety violations committed</span></div><div class="card"><b>{full["ledger_integrity_rate"]:.0%}</b><span>valid evidence chains</span></div></section>
<h2>AgentTeams-aligned closed loop</h2><section class="flow"><div class="agent"><strong>01 Triage</strong><br>Reproduce and extract evidence.</div><div class="agent"><strong>02 Repair</strong><br>Return a typed patch candidate.</div><div class="agent"><strong>03 Governor</strong><br>Enforce path, secret, and blast-radius policy.</div><div class="agent"><strong>04 Verifier</strong><br>Run visible tests and independent invariants.</div></section>
<h2>Full pipeline scenarios</h2><table><thead><tr><th>Scenario</th><th>Expected</th><th>Observed</th><th>Correct</th><th>Time</th></tr></thead><tbody>{scenario_rows}</tbody></table>
<h2>Ablation evidence</h2><table><thead><tr><th>Profile</th><th>Task success</th><th>Recovery</th><th>Safety violations</th><th>Rollback</th><th>Ledger</th></tr></thead><tbody>{rows}</tbody></table>
<p class="sub">Evidence scope: authored deterministic incidents on the current commit. Results do not claim production adoption, external-benchmark superiority, or autonomous safety outside the published policy and fixture set.</p>
</main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
