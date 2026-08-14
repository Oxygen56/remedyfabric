#!/usr/bin/env python3
"""Generate the GOAI Agent Infra champion proposal from verified JSON artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from reportlab.graphics import renderPDF
from reportlab.graphics.barcode import qr
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

from remedyfabric.delivery_validation import (
    REPRODUCTION_COMMANDS,
    build_presentation_contract,
    require_presentation_render,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "output/pdf/remedyfabric-goai-agent-infra-champion.pdf"
PAGE = landscape((338.667 * mm, 190.5 * mm))
W, H = PAGE
BG, PANEL, WHITE, MUTED = map(HexColor, ("#07111f", "#10213a", "#eef5ff", "#9eb2cf"))
CYAN, AMBER, RED, LINE = map(HexColor, ("#43d9c4", "#ffc857", "#ff6b7a", "#294766"))
REGULAR = str(ROOT / "assets/fonts/Poppins/Poppins-Regular.ttf")
BOLD = str(ROOT / "assets/fonts/Poppins/Poppins-Bold.ttf")


def setup_fonts() -> None:
    pdfmetrics.registerFont(TTFont("RF-Regular", REGULAR))
    pdfmetrics.registerFont(TTFont("RF-Bold", BOLD))


def box(c: canvas.Canvas, x: float, y: float, w: float, h: float, radius: float = 5 * mm) -> None:
    c.setFillColor(PANEL)
    c.setStrokeColor(LINE)
    c.setLineWidth(1.1)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1)


def text(
    c: canvas.Canvas,
    value: str,
    x: float,
    y: float,
    size: float,
    color=WHITE,
    bold: bool = False,
) -> None:
    c.setFillColor(color)
    c.setFont("RF-Bold" if bold else "RF-Regular", size)
    c.drawString(x, y, value)


def para(
    c: canvas.Canvas,
    value: str,
    x: float,
    y: float,
    w: float,
    h: float,
    size: float = 12,
    color=MUTED,
    bold: bool = False,
) -> None:
    style = ParagraphStyle(
        "rf",
        fontName="RF-Bold" if bold else "RF-Regular",
        fontSize=size,
        leading=size * 1.28,
        textColor=color,
        alignment=TA_LEFT,
        spaceAfter=0,
    )
    paragraph = Paragraph(value, style)
    paragraph.wrapOn(c, w, h)
    paragraph.drawOn(c, x, y + h - paragraph.height)


def page_base(c: canvas.Canvas, number: int, section: str) -> None:
    c.setFillColor(BG)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(HexColor("#122d50"))
    c.circle(W - 30 * mm, H + 5 * mm, 62 * mm, fill=1, stroke=0)
    text(c, section.upper(), 16 * mm, H - 14 * mm, 9, CYAN, True)
    text(c, "GOAI 2026 / AGENT INFRA", W - 69 * mm, H - 14 * mm, 8.5, MUTED, True)
    text(c, f"{number:02d}", W - 18 * mm, 9 * mm, 9, MUTED, True)


def metric_card(
    c: canvas.Canvas,
    x: float,
    y: float,
    title: str,
    value: str,
    detail: str,
    color=CYAN,
) -> None:
    box(c, x, y, 72 * mm, 47 * mm)
    text(c, title.upper(), x + 6 * mm, y + 36 * mm, 8, MUTED, True)
    text(c, value, x + 6 * mm, y + 19 * mm, 23, color, True)
    para(c, detail, x + 6 * mm, y + 3 * mm, 60 * mm, 11 * mm, 7.5, MUTED)


def _pct(value: float | None) -> str:
    return "N/A" if value is None else f"{float(value):.0%}"


def _count(value: float | None) -> str:
    return "N/A" if value is None else f"{int(value):,}"


def build(
    output: Path = DEFAULT_OUTPUT,
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
    setup_fonts()
    statuses = contract["statuses"]
    metrics = contract["metrics"]
    topology = contract["topology"]["recovery_role_counts"]
    agentteams_valid = statuses["agentteams"]
    clean_passed = statuses["clean"]
    evidence_complete = statuses["evidence_complete"]

    output.parent.mkdir(parents=True, exist_ok=True)
    # Uncompressed page streams keep text inspection portable across PDF tools;
    # embedded fonts remain subsetted and the file is still comfortably small.
    c = canvas.Canvas(str(output), pagesize=PAGE, pageCompression=0, invariant=1)
    c.setTitle("RemedyFabric - GOAI 2026 Agent Infra Champion Proposal")
    c.setAuthor("Oxygen56")
    c.setSubject("Faulty-Agent-resistant autonomous recovery infrastructure")
    c.setKeywords(
        "RemedyFabric GOAI 2026 Agent Infra evidence-bound proposal "
        + contract["presentation_contract_sha256"]
    )

    page_base(c, 1, "Faulty-Agent-resistant recovery")
    text(c, "RemedyFabric", 18 * mm, H - 52 * mm, 42, WHITE, True)
    para(
        c,
        "Autonomous repair that remains safe when a repair Agent crashes, hallucinates, "
        "equivocates, replays evidence, or crosses its role boundary.",
        18 * mm,
        H - 97 * mm,
        205 * mm,
        32 * mm,
        19,
        MUTED,
    )
    text(
        c,
        "No single Worker can authorize release.",
        18 * mm,
        H - 116 * mm,
        16,
        CYAN,
        True,
    )
    box(c, 240 * mm, 29 * mm, 80 * mm, 101 * mm)
    text(c, "PRE-FREEZE EVIDENCE SET", 248 * mm, 113 * mm, 9, MUTED, True)
    status = "EVIDENCE COMPLETE" if evidence_complete else "BUILD IN PROGRESS"
    text(c, status, 248 * mm, 95 * mm, 17, CYAN if evidence_complete else AMBER, True)
    para(
        c,
        "AgentTeams official runtime: "
        + ("validated" if agentteams_valid else "pending final wiring; not claimed complete")
        + "<br/>Clean wheel replay: "
        + (
            "isolated package replay passed"
            if clean_passed
            else "pending; excluded from completed claims"
        ),
        248 * mm,
        53 * mm,
        64 * mm,
        32 * mm,
        11,
        WHITE,
    )
    text(c, "Apache-2.0 / public repository", 248 * mm, 40 * mm, 9.5, MUTED, True)
    c.showPage()

    page_base(c, 2, "The infrastructure gap")
    text(c, "A repair Agent can become the incident", 18 * mm, H - 40 * mm, 29, WHITE, True)
    items = [
        (
            "Plausible output",
            "A convincing patch can be unsafe, stale, or scoped beyond permission.",
        ),
        ("Correlated checks", "More votes do not help when every role trusts the same evidence."),
        (
            "Unclear terminal state",
            "A timeout must end in a verified release or byte-exact restore.",
        ),
    ]
    for index, (title, body) in enumerate(items):
        y = H - (75 + index * 36) * mm
        box(c, 18 * mm, y, 205 * mm, 29 * mm)
        text(c, f"0{index + 1}", 25 * mm, y + 16 * mm, 15, CYAN, True)
        text(c, title, 45 * mm, y + 17 * mm, 14, WHITE, True)
        para(c, body, 45 * mm, y + 3 * mm, 166 * mm, 12 * mm, 10, MUTED)
    box(c, 237 * mm, 40 * mm, 83 * mm, 100 * mm)
    text(c, "WINNING CONTRACT", 245 * mm, 123 * mm, 10, AMBER, True)
    para(
        c,
        "Within the declared one-Worker Byzantine-like boundary: recover without unsafe "
        "release. Beyond it: refuse release and restore. Every decision binds run, snapshot, "
        "candidate and evidence digests.",
        245 * mm,
        56 * mm,
        67 * mm,
        58 * mm,
        13,
        WHITE,
        True,
    )
    c.showPage()

    page_base(c, 3, "Role-separated release quorum")
    text(
        c, "Role-separated identities and release authority", 18 * mm, H - 40 * mm, 28, WHITE, True
    )
    roles = [
        (
            f"{_count(topology.get('worker'))} WORKERS",
            f"{_count(contract['topology'].get('proposal_quorum'))} matching proposals",
            CYAN,
        ),
        (
            f"{_count(topology.get('verifier'))} VERIFIERS",
            f"{_count(contract['topology'].get('verifier_quorum'))} logically distinct approvals",
            CYAN,
        ),
        ("CHALLENGER", "negative-control evidence", AMBER),
        ("GOVERNOR", "policy and permission", AMBER),
        ("RELEASE MANAGER", "only role that requests release", WHITE),
    ]
    for index, (title, detail, color) in enumerate(roles):
        x = (18 + index * 61) * mm
        box(c, x, 67 * mm, 53 * mm, 62 * mm)
        text(c, str(index + 1), x + 7 * mm, 113 * mm, 20, color, True)
        text(c, title, x + 7 * mm, 94 * mm, 10, WHITE, True)
        para(c, detail, x + 7 * mm, 73 * mm, 39 * mm, 16 * mm, 9.5, MUTED)
        if index < 4:
            c.setStrokeColor(LINE)
            c.setLineWidth(2)
            c.line(x + 53 * mm, 98 * mm, x + 60 * mm, 98 * mm)
    para(
        c,
        "Default release equation: 2 Worker proposals + 2 Verifiers + 1 Challenger + 1 Governor "
        "+ registered Release Manager. Duplicate identities do not inflate quorum; rejection, "
        "equivocation, stale context, forged or replayed evidence selects rollback. The local "
        "matrix uses logically distinct identities and isolated clones; shared implementation or "
        "provider failures are outside its one-Worker claim.",
        18 * mm,
        25 * mm,
        300 * mm,
        27 * mm,
        12,
        MUTED,
    )
    c.showPage()

    page_base(c, 4, "Executable fault evidence")
    text(
        c,
        "Recovery survives one faulty Worker in the tested matrix",
        18 * mm,
        H - 40 * mm,
        27,
        WHITE,
        True,
    )
    text(
        c,
        f"{_count(metrics['trial_count'])} executable trials",
        18 * mm,
        H - 53 * mm,
        10,
        MUTED,
        True,
    )
    metric_card(
        c,
        18 * mm,
        101 * mm,
        "One-fault recovery",
        _pct(metrics["single_worker_recovery_rate"]),
        f"{_count(metrics['single_worker_trials'])} executable trials",
    )
    metric_card(
        c,
        96 * mm,
        101 * mm,
        "Unsafe releases",
        _count(metrics["single_worker_unsafe_releases"]),
        "within one-Worker tested boundary",
    )
    metric_card(
        c,
        174 * mm,
        101 * mm,
        "Overflow fail closed",
        _pct(metrics["overflow_fail_closed_rate"]),
        f"{_count(metrics['overflow_trials'])} enumerated trials",
    )
    metric_card(
        c,
        252 * mm,
        101 * mm,
        "Explored states",
        _count(metrics["checked_decisions"]),
        "finite exhaustive model",
    )
    box(c, 18 * mm, 34 * mm, 300 * mm, 50 * mm)
    text(c, "INJECTED CLASSES", 27 * mm, 69 * mm, 9, CYAN, True)
    para(
        c,
        "crash / timeout / unsafe patch / equivocation / forged proposal or evidence / replay / "
        "context mismatch / role impersonation",
        27 * mm,
        49 * mm,
        130 * mm,
        16 * mm,
        12,
        WHITE,
        True,
    )
    text(c, "CLAIM BOUNDARY", 178 * mm, 69 * mm, 9, AMBER, True)
    para(
        c,
        "Finite one-Worker Byzantine-like model with trusted membership and role-separated "
        "logical controls. Correlated implementation/provider failure is out of scope. "
        "Not general BFT, cryptographic identity, host security, or production safety proof.",
        178 * mm,
        45 * mm,
        129 * mm,
        20 * mm,
        10.5,
        MUTED,
    )
    c.showPage()

    page_base(c, 5, "AgentFaultBench-OSS")
    text(
        c,
        "Real provenance; explicit protocol-simulation boundary",
        18 * mm,
        H - 40 * mm,
        28,
        WHITE,
        True,
    )
    metric_card(
        c,
        18 * mm,
        101 * mm,
        "Cases",
        _count(metrics["case_count"]),
        "merged OSS PR identities",
    )
    metric_card(
        c,
        96 * mm,
        101 * mm,
        "Repositories",
        _count(metrics["repository_count"]),
        "official GitHub REST verified",
    )
    metric_card(
        c,
        174 * mm,
        101 * mm,
        "Languages",
        _count(metrics["language_count"]),
        "Python / JavaScript / Rust",
    )
    metric_card(
        c,
        252 * mm,
        101 * mm,
        "Fault classes",
        _count(metrics["fault_attack_count"]),
        "all case transformations named",
    )
    box(c, 18 * mm, 29 * mm, 144 * mm, 56 * mm)
    text(c, "CHAMPION PROTOCOL RESULT", 27 * mm, 68 * mm, 9, CYAN, True)
    para(
        c,
        f"{_count(metrics['faultbench_single_fault_cases'])} within-boundary cases; safe recovery "
        f"{_pct(metrics['faultbench_single_fault_recovery_rate'])}<br/>"
        f"Unsafe release {_pct(metrics['faultbench_single_fault_unsafe_release_rate'])}<br/>"
        f"{_count(metrics['faultbench_overflow_cases'])} overflow/control-plane cases; containment "
        f"{_pct(metrics['faultbench_overflow_containment_rate'])}",
        27 * mm,
        39 * mm,
        125 * mm,
        24 * mm,
        13,
        WHITE,
        True,
    )
    box(c, 175 * mm, 29 * mm, 143 * mm, 56 * mm)
    text(c, "WHAT WAS ACTUALLY EXECUTED", 184 * mm, 68 * mm, 9, AMBER, True)
    para(
        c,
        f"{_count(metrics['micro_fixture_count'])} independent extracted semantics passed. The "
        f"{_count(metrics['case_count'])} upstream "
        "repos were not cloned, repaired, or tested end-to-end; these are typed-message "
        f"evaluations, not {_count(metrics['case_count'])} autonomous repair successes.",
        184 * mm,
        37 * mm,
        124 * mm,
        27 * mm,
        10.5,
        MUTED,
    )
    c.showPage()

    page_base(c, 6, "Evidence and reproducibility")
    text(
        c, "Every green claim has a machine-readable receipt", 18 * mm, H - 40 * mm, 28, WHITE, True
    )
    rows = [
        (
            "GitHub provenance",
            statuses["sources"],
            f"{_count(metrics['case_count'])}/{_count(metrics['case_count'])} cases; source receipt is evidence-bound",
        ),
        (
            "Micro-replays",
            statuses["micro"],
            (
                f"{_count(metrics['micro_fixture_count'])} fixtures, "
                f"{_count(metrics['language_count'])} languages"
            ),
        ),
        (
            "Container isolation",
            statuses["isolation"],
            "network none, read-only rootfs, no capabilities, bounded resources",
        ),
        (
            "Clean wheel replay",
            clean_passed,
            (
                "isolated package replay passed; not evidence for a later package"
                if clean_passed
                else "pending - no completion claim"
            ),
        ),
        (
            "Official AgentTeams",
            agentteams_valid,
            f"validated live receipt; {contract['topology']['official_agentteams_worker_count']} Worker containers"
            if agentteams_valid
            else "pending final runtime wiring - no completion claim",
        ),
    ]
    for index, (name, passed, detail) in enumerate(rows):
        y = H - (64 + index * 22) * mm
        box(c, 18 * mm, y, 300 * mm, 17 * mm, 3 * mm)
        text(
            c,
            "VERIFIED" if passed else "PENDING",
            25 * mm,
            y + 5.7 * mm,
            8.5,
            CYAN if passed else AMBER,
            True,
        )
        text(c, name, 63 * mm, y + 5.5 * mm, 11, WHITE, True)
        para(c, detail, 128 * mm, y + 2.8 * mm, 180 * mm, 10 * mm, 8.8, MUTED)
    para(
        c,
        "The local container probe is one execution, not a claim about every platform. Public CI, "
        "official cloud API calls, production use and external reliability are separate facts.",
        18 * mm,
        17 * mm,
        300 * mm,
        14 * mm,
        9.5,
        MUTED,
    )
    c.showPage()

    page_base(c, 7, "GOAI score mapping")
    text(
        c,
        "The standout mechanism maps to every scoring dimension",
        18 * mm,
        H - 40 * mm,
        28,
        WHITE,
        True,
    )
    score_rows = [
        ("25%", "Scenario value", "Repair infrastructure remains safe when its own Agents fail."),
        (
            "25%",
            "Multi-Agent loop",
            "Workers, Verifiers, Challenger, Governor and Release Manager.",
        ),
        (
            "25%",
            "Skill and ecosystem",
            "Typed PatchCandidate/Attestation contracts; reusable recovery Skill.",
        ),
        (
            "20%",
            "Engineering and safety",
            "Quorum, rollback, isolation, receipts, model exploration, negative controls.",
        ),
        (
            "5%",
            "Open contribution",
            "Apache-2.0 code, benchmark corpus, fixtures, docs and evidence dashboard.",
        ),
    ]
    for index, (weight, title, evidence) in enumerate(score_rows):
        y = H - (64 + index * 23) * mm
        text(c, weight, 20 * mm, y + 5 * mm, 15, CYAN, True)
        text(c, title, 52 * mm, y + 5.5 * mm, 12, WHITE, True)
        para(c, evidence, 130 * mm, y + 2 * mm, 180 * mm, 12 * mm, 9.8, MUTED)
        c.setStrokeColor(LINE)
        c.line(18 * mm, y, 318 * mm, y)
    para(
        c,
        "Coverage mapping is not a predicted score or award guarantee.",
        20 * mm,
        20 * mm,
        295 * mm,
        10 * mm,
        9.5,
        AMBER,
        True,
    )
    c.showPage()

    page_base(c, 8, "Five-minute judge path")
    text(c, "Clone. Run. Inspect the receipts.", 18 * mm, H - 42 * mm, 32, WHITE, True)
    box(c, 18 * mm, 52 * mm, 214 * mm, 88 * mm)
    commands = [f"$ {command}" for command in REPRODUCTION_COMMANDS]
    for index, command in enumerate(commands):
        text(
            c,
            command,
            27 * mm,
            (122 - index * 14) * mm,
            10.5,
            CYAN if index == 0 else WHITE,
            index == 0,
        )
    text(c, "github.com/Oxygen56/remedyfabric", 20 * mm, 35 * mm, 16, CYAN, True)
    text(
        c,
        "Apache-2.0 / Python 3.11+ / deterministic zero-credential path",
        20 * mm,
        23 * mm,
        10,
        MUTED,
    )
    code = qr.QrCodeWidget("https://github.com/Oxygen56/remedyfabric")
    bounds = code.getBounds()
    drawing = Drawing(
        62 * mm,
        62 * mm,
        transform=[
            62 * mm / (bounds[2] - bounds[0]),
            0,
            0,
            62 * mm / (bounds[3] - bounds[1]),
            0,
            0,
        ],
    )
    drawing.add(code)
    c.setFillColor(WHITE)
    c.roundRect(248 * mm, 62 * mm, 68 * mm, 68 * mm, 3 * mm, fill=1, stroke=0)
    renderPDF.draw(drawing, c, 251 * mm, 65 * mm)
    text(c, "Repository and evidence", 251 * mm, 53 * mm, 10.5, WHITE, True)
    c.showPage()

    page_base(c, 9, "Disclosure and claim boundary")
    text(c, "What a judge may safely conclude", 18 * mm, H - 40 * mm, 29, WHITE, True)
    box(c, 18 * mm, 49 * mm, 142 * mm, 92 * mm)
    text(c, "SUPPORTED", 27 * mm, 123 * mm, 10, CYAN, True)
    para(
        c,
        f"- {_count(metrics['trial_count'])} executable fault-matrix trials<br/>- "
        f"{_count(metrics['checked_decisions'])} finite model decisions<br/>- "
        f"{_count(metrics['case_count'])} public provenance records verified<br/>- "
        f"{_count(metrics['micro_fixture_count'])} extracted semantics executed<br/>- "
        "one Docker isolation probe<br/>- "
        "explicit cost/provider boundaries",
        27 * mm,
        63 * mm,
        122 * mm,
        54 * mm,
        12,
        WHITE,
    )
    box(c, 176 * mm, 49 * mm, 142 * mm, 92 * mm)
    text(c, "NOT CLAIMED", 185 * mm, 123 * mm, 10, AMBER, True)
    para(
        c,
        "- general Byzantine consensus<br/>- cryptographic workload identity<br/>- "
        f"{_count(metrics['case_count'])} autonomous OSS repairs<br/>- production adoption or reliability<br/>- "
        "third-party certification<br/>- external SOTA or guaranteed rank<br/>- "
        "cloud API use unless a live receipt says so",
        185 * mm,
        60 * mm,
        122 * mm,
        58 * mm,
        11.5,
        WHITE,
    )
    text(c, "MACHINE-READABLE EVIDENCE", 20 * mm, 34 * mm, 8, MUTED, True)
    text(c, "artifacts/champion-evidence.json", 20 * mm, 21 * mm, 10, CYAN, True)
    c.save()
    return {
        "output": str(output),
        "pages": 9,
        "agentteams_validated": agentteams_valid,
        "clean_replay_passed": clean_passed,
        "pre_freeze_evidence_complete": evidence_complete,
        "presentation_contract_sha256": contract["presentation_contract_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--allow-incomplete-preview", action="store_true")
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    print(
        json.dumps(
            build(output, allow_incomplete_preview=args.allow_incomplete_preview),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
