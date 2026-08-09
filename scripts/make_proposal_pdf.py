#!/usr/bin/env python3
"""Generate the GOAI submission proposal PDF from verified repository artifacts."""

from __future__ import annotations

import json
from pathlib import Path

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

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output/pdf/remedyfabric-goai-2026-proposal.pdf"
PAGE = landscape((338.667 * mm, 190.5 * mm))
W, H = PAGE
BG, PANEL, WHITE, MUTED = map(HexColor, ("#07111f", "#10213a", "#eef5ff", "#9eb2cf"))
CYAN, AMBER, RED, LINE = map(HexColor, ("#43d9c4", "#ffc857", "#ff6b7a", "#294766"))
REGULAR = "/System/Library/Fonts/Supplemental/Arial.ttf"
BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"


def setup_fonts() -> None:
    pdfmetrics.registerFont(TTFont("RF-Regular", REGULAR))
    pdfmetrics.registerFont(TTFont("RF-Bold", BOLD))


def box(c: canvas.Canvas, x: float, y: float, w: float, h: float, radius: float = 6 * mm) -> None:
    c.setFillColor(PANEL)
    c.setStrokeColor(LINE)
    c.setLineWidth(1.2)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1)


def text(
    c: canvas.Canvas, value: str, x: float, y: float, size: float, color=WHITE, bold=False
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
    size=17,
    color=MUTED,
    bold=False,
) -> None:
    style = ParagraphStyle(
        "rf",
        fontName="RF-Bold" if bold else "RF-Regular",
        fontSize=size,
        leading=size * 1.32,
        textColor=color,
        alignment=TA_LEFT,
        spaceAfter=0,
    )
    p = Paragraph(value, style)
    p.wrapOn(c, w, h)
    p.drawOn(c, x, y + h - p.height)


def page_base(c: canvas.Canvas, number: int, section: str) -> None:
    c.setFillColor(BG)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(HexColor("#122d50"))
    c.circle(W - 30 * mm, H + 5 * mm, 62 * mm, fill=1, stroke=0)
    text(c, section.upper(), 16 * mm, H - 14 * mm, 10, CYAN, True)
    text(c, "GOAI 2026 · AGENT INFRA", W - 68 * mm, H - 14 * mm, 9, MUTED, True)
    text(c, f"{number:02d}", W - 18 * mm, 9 * mm, 9, MUTED, True)


def metric_card(c: canvas.Canvas, x: float, y: float, title: str, value: str, color=CYAN) -> None:
    box(c, x, y, 72 * mm, 39 * mm)
    text(c, title.upper(), x + 6 * mm, y + 27 * mm, 8.5, MUTED, True)
    text(c, value, x + 6 * mm, y + 10 * mm, 25, color, True)


def build() -> None:
    setup_fonts()
    benchmark = json.loads((ROOT / "artifacts/benchmark.json").read_text(encoding="utf-8"))
    profiles = {item["profile"]: item for item in benchmark["profiles"]}
    full = profiles["full"]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(OUTPUT), pagesize=PAGE, pageCompression=1)
    c.setTitle("RemedyFabric - GOAI 2026 Agent Infra Proposal")
    c.setAuthor("Oxygen56")

    page_base(c, 1, "Evidence-first recovery infrastructure")
    text(c, "RemedyFabric", 18 * mm, H - 52 * mm, 42, WHITE, True)
    para(
        c,
        "Autonomous software repair that can prove what changed, why it was allowed, and whether the system actually recovered.",
        18 * mm,
        H - 96 * mm,
        208 * mm,
        32 * mm,
        20,
        MUTED,
    )
    text(
        c,
        "Diagnose → Propose → Govern → Verify → Commit or Roll back",
        18 * mm,
        H - 116 * mm,
        15,
        CYAN,
        True,
    )
    box(c, 246 * mm, 31 * mm, 72 * mm, 93 * mm)
    text(c, "TARGET", 254 * mm, 108 * mm, 9, MUTED, True)
    para(
        c,
        "Agent Infra champion<br/>and overall grand prize",
        254 * mm,
        71 * mm,
        56 * mm,
        32 * mm,
        18,
        WHITE,
        True,
    )
    text(c, "Apache-2.0", 254 * mm, 53 * mm, 12, AMBER, True)
    text(c, "Offline demo · USD 0.00", 254 * mm, 40 * mm, 10, CYAN, True)
    c.showPage()

    page_base(c, 2, "Problem and value")
    text(c, "Plausible patches are not recovery evidence", 18 * mm, H - 40 * mm, 30, WHITE, True)
    items = [
        (
            "Repair generator",
            "Can propose a convincing change, but should not approve or commit itself.",
        ),
        (
            "Operational risk",
            "A test may pass while invariants fail; a valid fix may hide an unauthorized workflow or credential change.",
        ),
        (
            "Infrastructure gap",
            "Teams need a provider-neutral layer for blast radius, independent verification, rollback, receipts, and metrics.",
        ),
    ]
    for idx, (title, body) in enumerate(items):
        y = H - (74 + idx * 36) * mm
        box(c, 18 * mm, y, 200 * mm, 29 * mm)
        text(c, f"0{idx + 1}", 25 * mm, y + 17 * mm, 15, CYAN, True)
        text(c, title, 45 * mm, y + 18 * mm, 14, WHITE, True)
        para(c, body, 45 * mm, y + 3 * mm, 163 * mm, 13 * mm, 10, MUTED)
    box(c, 233 * mm, H - 148 * mm, 85 * mm, 98 * mm)
    text(c, "SUCCESS CONTRACT", 241 * mm, H - 66 * mm, 10, AMBER, True)
    para(
        c,
        "A judge clones the repository, runs one command without credentials, observes both repairs and adversarial rejection, verifies the ledger, and reproduces every number.",
        241 * mm,
        H - 127 * mm,
        68 * mm,
        53 * mm,
        14,
        WHITE,
        True,
    )
    c.showPage()

    page_base(c, 3, "AgentTeams-aligned loop")
    text(
        c,
        "Four specialized Workers, one controlled transaction",
        18 * mm,
        H - 40 * mm,
        29,
        WHITE,
        True,
    )
    agents = [
        ("TRIAGE", "Reproduce\nand diagnose"),
        ("REPAIR", "Typed patch\nSkill"),
        ("GOVERN", "Fail-closed\npolicy"),
        ("VERIFY", "Tests and\ninvariants"),
    ]
    for idx, (name, body) in enumerate(agents):
        x = (18 + idx * 78) * mm
        box(c, x, 65 * mm, 66 * mm, 63 * mm)
        c.setFillColor(CYAN)
        c.circle(x + 12 * mm, 113 * mm, 6 * mm, fill=1, stroke=0)
        text(c, str(idx + 1), x + 10.4 * mm, 110.5 * mm, 11, BG, True)
        text(c, name, x + 8 * mm, 93 * mm, 17, WHITE, True)
        para(c, body.replace("\n", "<br/>"), x + 8 * mm, 70 * mm, 48 * mm, 18 * mm, 13, MUTED)
        if idx < 3:
            c.setStrokeColor(AMBER)
            c.setLineWidth(2.5)
            c.line(x + 66 * mm, 96 * mm, x + 77 * mm, 96 * mm)
    para(
        c,
        "Manager snapshots the workspace, applies only approved typed edits, then commits or restores every file byte-for-byte. Shared structured state plus the hash-chained ledger provide the required context and observability mechanisms.",
        18 * mm,
        28 * mm,
        300 * mm,
        25 * mm,
        13,
        MUTED,
    )
    c.showPage()

    page_base(c, 4, "Safety and failure recovery")
    text(
        c,
        "The safest autonomous action is sometimes no action",
        18 * mm,
        H - 40 * mm,
        29,
        WHITE,
        True,
    )
    protections = [
        ("Visible-test overfit", "ROLL BACK", AMBER),
        ("Delete tests or invariants", "BLOCK", RED),
        ("Modify CI / repository policy", "BLOCK", RED),
        ("Escape workspace or introduce a secret", "BLOCK", RED),
    ]
    for idx, (probe, outcome, color) in enumerate(protections):
        y = H - (72 + idx * 27) * mm
        box(c, 18 * mm, y, 210 * mm, 21 * mm, 4 * mm)
        text(c, probe, 25 * mm, y + 7 * mm, 13, WHITE, True)
        text(c, outcome, 184 * mm, y + 7 * mm, 12, color, True)
    box(c, 242 * mm, 43 * mm, 76 * mm, 95 * mm)
    text(c, "DEFENSE IN DEPTH", 250 * mm, 122 * mm, 10, CYAN, True)
    para(
        c,
        "No shell<br/>Scrubbed environment<br/>Bounded timeout<br/>Protected paths<br/>Old-content precondition<br/>Independent invariants<br/>Byte-exact restore<br/>Hash-chain receipts",
        250 * mm,
        54 * mm,
        60 * mm,
        62 * mm,
        12,
        WHITE,
    )
    c.showPage()

    page_base(c, 5, "Verified benchmark")
    text(
        c,
        "Every headline number comes from the current artifact",
        18 * mm,
        H - 40 * mm,
        29,
        WHITE,
        True,
    )
    metric_card(c, 18 * mm, 103 * mm, "Task success", f"{full['task_success_rate']:.0%}")
    metric_card(c, 96 * mm, 103 * mm, "Recovery success", f"{full['recovery_success_rate']:.0%}")
    metric_card(
        c, 174 * mm, 103 * mm, "Unsafe commits", f"{full['safety_violation_rate']:.0%}", CYAN
    )
    metric_card(c, 252 * mm, 103 * mm, "Valid ledgers", f"{full['ledger_integrity_rate']:.0%}")
    headers = ["Profile", "Task success", "Recovery", "Safety violations", "Rollback"]
    xs = [20, 92, 145, 200, 266]
    for x, header in zip(xs, headers):
        text(c, header.upper(), x * mm, 88 * mm, 8, MUTED, True)
    for row, profile in enumerate(benchmark["profiles"]):
        y = (76 - row * 10) * mm
        values = [
            profile["profile"],
            f"{profile['task_success_rate']:.1%}",
            f"{profile['recovery_success_rate']:.1%}",
            f"{profile['safety_violation_rate']:.1%}",
            f"{profile['rollback_success_rate']:.1%}",
        ]
        for x, value in zip(xs, values):
            text(c, value, x * mm, y, 10, WHITE if row == 0 else MUTED, row == 0)
    para(
        c,
        "Scope: eight transparent authored deterministic incidents. These results prove the published mechanisms on this commit; they do not claim production adoption, external benchmark superiority, or universal repair coverage.",
        18 * mm,
        7 * mm,
        300 * mm,
        16 * mm,
        10,
        MUTED,
    )
    c.showPage()

    page_base(c, 6, "Skill and ecosystem reuse")
    text(c, "Provider-neutral core, reusable Skill boundary", 18 * mm, H - 40 * mm, 29, WHITE, True)
    columns = [
        (
            "INPUT",
            "Incident ID\nIsolated workspace\nReproduction command\nFailure evidence\nAllowed and protected paths",
        ),
        (
            "PATCH CANDIDATE",
            "Skill and version\nDiagnosis and confidence\nRelative paths\nComplete old and new content\nReason and provider cost",
        ),
        (
            "INDEPENDENT CONTROL",
            "Governor approval\nVerifier receipt\nCommit or rollback\nLedger hash\nTerminal outcome",
        ),
    ]
    for idx, (title, body) in enumerate(columns):
        x = (18 + idx * 102) * mm
        box(c, x, 56 * mm, 90 * mm, 83 * mm)
        text(c, title, x + 8 * mm, 123 * mm, 11, CYAN if idx != 1 else AMBER, True)
        para(c, body.replace("\n", "<br/>"), x + 8 * mm, 66 * mm, 74 * mm, 49 * mm, 13, WHITE)
    text(
        c,
        "Official AgentTeams CRDs included · local zero-credential runtime mirrors the same roles",
        18 * mm,
        36 * mm,
        13,
        WHITE,
        True,
    )
    text(
        c,
        "Alibaba Cloud Skills are an optional declared integration; baseline evidence does not pretend a live cloud run.",
        18 * mm,
        24 * mm,
        11,
        MUTED,
    )
    c.showPage()

    page_base(c, 7, "GOAI score coverage")
    text(c, "Artifacts mapped to every official dimension", 18 * mm, H - 40 * mm, 29, WHITE, True)
    rows = [
        (
            "25%",
            "Scenario and replication",
            "Cross-team repository recovery; one-command offline run",
        ),
        ("25%", "Multi-Agent closed loop", "Four Workers, Manager, terminal commit/block/rollback"),
        (
            "25%",
            "Skill engineering and reuse",
            "Versioned typed Skill; provider replacement contract",
        ),
        (
            "20%",
            "Engineering, safety and audit",
            "Policy, invariants, rollback, receipts, tests, ablations",
        ),
        ("5%", "Open contribution", "Apache-2.0 source, fixtures, docs, dashboard and CRDs"),
    ]
    for idx, (weight, title, evidence) in enumerate(rows):
        y = H - (63 + idx * 21) * mm
        text(c, weight, 20 * mm, y + 6 * mm, 16, CYAN, True)
        text(c, title, 48 * mm, y + 7 * mm, 13, WHITE, True)
        text(c, evidence, 133 * mm, y + 7 * mm, 11, MUTED)
        c.setStrokeColor(LINE)
        c.line(18 * mm, y, 317 * mm, y)
    text(c, "Claim boundary", 20 * mm, 20 * mm, 11, AMBER, True)
    para(
        c,
        "Artifact coverage is not a predicted judge score. Local execution, live AgentTeams deployment, public CI, official submission and production adoption are reported separately.",
        58 * mm,
        5 * mm,
        255 * mm,
        13 * mm,
        10,
        MUTED,
    )
    c.showPage()

    page_base(c, 8, "Reproduce and inspect")
    text(c, "Evidence before claims", 18 * mm, H - 44 * mm, 36, WHITE, True)
    box(c, 18 * mm, 57 * mm, 210 * mm, 80 * mm)
    commands = [
        "$ python -m pip install -e .",
        "$ python -m unittest discover -s tests -v",
        "$ remedyfabric benchmark --output artifacts/benchmark.json",
        "$ remedyfabric report --benchmark artifacts/benchmark.json",
    ]
    for idx, command in enumerate(commands):
        text(c, command, 27 * mm, (120 - idx * 15) * mm, 12, CYAN if idx == 0 else WHITE, idx == 0)
    text(c, "github.com/Oxygen56/remedyfabric", 20 * mm, 38 * mm, 18, CYAN, True)
    text(c, "Apache-2.0 · Python 3.11+ · no API key required", 20 * mm, 25 * mm, 11, MUTED)
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
    renderPDF.draw(drawing, c, 250 * mm, 61 * mm)
    text(c, "Repository and evidence", 252 * mm, 49 * mm, 11, WHITE, True)
    c.save()
    print(OUTPUT)


if __name__ == "__main__":
    build()
