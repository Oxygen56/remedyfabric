#!/usr/bin/env python3
"""Create a judge-facing champion MP4 from verified artifact JSON."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import tempfile
import textwrap
from pathlib import Path
from typing import Any

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont

from remedyfabric.delivery_validation import (
    build_contact_sheet_from_video,
    build_presentation_contract,
    caption_contract_sha256,
    require_presentation_render,
    video_caption_cues,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts/remedyfabric-champion-demo.mp4"
DEFAULT_PREVIEW = ROOT / "artifacts/video-preview.jpg"
WIDTH, HEIGHT, FPS = 1920, 1080, 6
FONT_REGULAR = str(ROOT / "assets/fonts/Poppins/Poppins-Regular.ttf")
FONT_BOLD = str(ROOT / "assets/fonts/Poppins/Poppins-Bold.ttf")
BG, PANEL, CYAN = "#07111f", "#10213a", "#43d9c4"
AMBER, WHITE, MUTED, RED = "#ffc857", "#eef5ff", "#9eb2cf", "#ff6b7a"


def _srt_timestamp(seconds: float) -> str:
    milliseconds = round(seconds * 1000)
    hours, remainder = divmod(milliseconds, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    whole_seconds, milliseconds = divmod(remainder, 1000)
    return f"{hours:02d}:{minutes:02d}:{whole_seconds:02d},{milliseconds:03d}"


def _write_srt(path: Path, contract: dict[str, Any]) -> None:
    blocks = []
    for cue in video_caption_cues(contract):
        blocks.append(
            "\n".join(
                (
                    str(cue["scene"]),
                    (
                        f"{_srt_timestamp(float(cue['start_seconds']))} --> "
                        f"{_srt_timestamp(float(cue['end_seconds']))}"
                    ),
                    f"{cue['title']}: {cue['caption']}",
                )
            )
        )
    path.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")


def _mux_silent_captions(
    video_input: Path,
    subtitles: Path,
    output: Path,
    contract: dict[str, Any],
) -> None:
    comment = (
        f"remedyfabric-presentation={contract['presentation_contract_sha256']};"
        f"caption={caption_contract_sha256(contract)}"
    )
    completed = subprocess.run(
        [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-v",
            "error",
            "-i",
            str(video_input),
            "-i",
            str(subtitles),
            "-map",
            "0:v:0",
            "-map",
            "1:0",
            "-c:v",
            "copy",
            "-c:s",
            "mov_text",
            "-metadata",
            f"comment={comment}",
            "-metadata:s:s:0",
            "language=eng",
            "-metadata:s:s:0",
            "title=Complete English captions",
            "-movflags",
            "+faststart",
            "-y",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"caption mux failed: {completed.stderr}")


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REGULAR, size)


def wrapped(
    draw: ImageDraw.ImageDraw,
    value: str,
    xy: tuple[int, int],
    width: int,
    size: int,
    fill: str,
    bold: bool = False,
    spacing: int = 12,
) -> None:
    average = max(10, int(width / (size * 0.56)))
    lines: list[str] = []
    for paragraph in value.split("\n"):
        lines.extend(textwrap.wrap(paragraph, width=average) or [""])
    draw.multiline_text(xy, "\n".join(lines), font=font(size, bold), fill=fill, spacing=spacing)


def base_frame(tag: str, progress: float) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.ellipse((1300, -420, 2300, 580), fill="#122d50")
    draw.text((90, 58), tag.upper(), font=font(24, True), fill=CYAN)
    label = "GOAI 2026 / AGENT INFRA"
    label_box = draw.textbbox((0, 0), label, font=font(22, True))
    draw.text((WIDTH - 90 - label_box[2], 52), label, font=font(22, True), fill=MUTED)
    draw.rounded_rectangle((90, 1015, 1830, 1027), radius=6, fill="#1f3855")
    draw.rounded_rectangle((90, 1015, 90 + int(1740 * progress), 1027), radius=6, fill=CYAN)
    return image, draw


def card(
    draw: ImageDraw.ImageDraw,
    bounds: tuple[int, int, int, int],
    title: str,
    value: str,
    detail: str = "",
    color: str = CYAN,
) -> None:
    draw.rounded_rectangle(bounds, radius=24, fill=PANEL, outline="#294566", width=2)
    x1, y1, x2, _ = bounds
    draw.text((x1 + 28, y1 + 24), title.upper(), font=font(19, True), fill=MUTED)
    draw.text((x1 + 28, y1 + 68), value, font=font(49, True), fill=color)
    if detail:
        wrapped(draw, detail, (x1 + 28, y1 + 137), x2 - x1 - 56, 19, MUTED)


def _pct(value: float | None) -> str:
    return "N/A" if value is None else f"{float(value):.0%}"


def _count(value: float | None) -> str:
    return "N/A" if value is None else f"{int(value):,}"


def render_scene(
    scene: int,
    local_time: float,
    progress: float,
    evidence: dict[str, Any],
) -> Image.Image:
    tags = [
        "Champion thesis",
        "Release quorum",
        "Fault injection",
        "AgentFaultBench-OSS",
        "Reproducibility",
        "Official AgentTeams",
        "Five-minute review",
    ]
    image, draw = base_frame(tags[scene], progress)
    agentteams_valid = evidence["agentteams_valid"]
    evidence_complete = evidence["pre_freeze_evidence_complete"]
    role_counts = evidence["role_counts"]
    metrics = evidence["contract_metrics"]
    statuses = evidence["statuses"]
    if scene == 0:
        draw.text((90, 170), "RemedyFabric", font=font(88, True), fill=WHITE)
        wrapped(
            draw,
            "When repair Agents fail, the recovery infrastructure must not fail with them.",
            (96, 300),
            1250,
            44,
            MUTED,
            True,
        )
        card(
            draw,
            (100, 555, 570, 815),
            "Within boundary",
            "RECOVER",
            f"one faulty Worker among {role_counts.get('worker', 'N/A')}",
        )
        card(
            draw,
            (610, 555, 1080, 815),
            "Unsafe release",
            _pct(metrics["faultbench_single_fault_unsafe_release_rate"]),
            "tested single-fault cases",
            CYAN,
        )
        card(
            draw,
            (1120, 555, 1590, 815),
            "Beyond boundary",
            "ROLL BACK",
            "enumerated overflow controls",
            AMBER,
        )
        draw.text(
            (100, 900), "No single Worker can authorize release.", font=font(32, True), fill=CYAN
        )
    elif scene == 1:
        draw.text(
            (90, 150), "A release is a role-separated decision", font=font(61, True), fill=WHITE
        )
        roles = [
            (
                f"{role_counts.get('worker', 'N/A')} WORKERS",
                f"{evidence['proposal_quorum']} matching patches",
            ),
            (
                f"{role_counts.get('verifier', 'N/A')} VERIFIERS",
                f"{evidence['verifier_quorum']} logically distinct test receipts",
            ),
            ("CHALLENGER", "negative controls"),
            ("GOVERNOR", "policy approval"),
            ("RELEASE", "separately authorized"),
        ]
        for index, (title, detail) in enumerate(roles):
            x = 80 + index * 365
            y = 350 + int(10 * math.sin(local_time * 2 + index))
            draw.rounded_rectangle(
                (x, y, x + 315, y + 285), radius=26, fill=PANEL, outline="#2a4d70", width=3
            )
            draw.ellipse((x + 25, y + 25, x + 89, y + 89), fill=CYAN if index < 2 else AMBER)
            draw.text((x + 47, y + 35), str(index + 1), font=font(30, True), fill=BG)
            draw.text((x + 25, y + 126), title, font=font(27, True), fill=WHITE)
            wrapped(draw, detail, (x + 25, y + 184), 260, 22, MUTED)
        draw.text(
            (90, 805),
            "Same run + snapshot + candidate + evidence digests",
            font=font(31, True),
            fill=CYAN,
        )
        draw.text(
            (90, 865),
            "Logical identities + isolated clones; correlated provider failure is out of scope",
            font=font(26),
            fill=MUTED,
        )
    elif scene == 2:
        draw.text(
            (90, 145), "The system is attacked, not merely tested", font=font(58, True), fill=WHITE
        )
        faults = [
            "crash / timeout",
            "unsafe patch",
            "equivocation",
            "forged evidence",
            "replay",
            "role impersonation",
        ]
        for index, fault in enumerate(faults):
            column, row = index % 3, index // 3
            x, y = 90 + column * 585, 305 + row * 210
            draw.rounded_rectangle(
                (x, y, x + 510, y + 150), radius=20, fill=PANEL, outline="#294766", width=2
            )
            draw.text((x + 28, y + 30), fault.upper(), font=font(27, True), fill=WHITE)
            draw.text((x + 28, y + 88), "evidence-bound decision", font=font(21), fill=MUTED)
        card(
            draw,
            (90, 770, 570, 970),
            "Executable trials",
            _count(metrics["trial_count"]),
            "real rollback/release terminal states",
        )
        card(
            draw,
            (610, 770, 1090, 970),
            "State decisions",
            _count(metrics["checked_decisions"]),
            "finite exhaustive model",
        )
        card(
            draw,
            (1130, 770, 1610, 970),
            "Overflow fail closed",
            _pct(metrics["overflow_fail_closed_rate"]),
            "enumerated negative controls",
        )
    elif scene == 3:
        draw.text(
            (90, 145),
            f"{_count(metrics['case_count'])} real OSS records - with a strict boundary",
            font=font(58, True),
            fill=WHITE,
        )
        card(
            draw,
            (90, 290, 465, 520),
            "Cases",
            _count(metrics["case_count"]),
            "merged PR identities",
        )
        card(
            draw,
            (500, 290, 875, 520),
            "Repositories",
            _count(metrics["repository_count"]),
            "official REST verified",
        )
        card(
            draw,
            (910, 290, 1285, 520),
            "Languages",
            _count(metrics["language_count"]),
            "Python / JS / Rust",
        )
        card(
            draw,
            (1320, 290, 1695, 520),
            "Fault classes",
            _count(metrics["fault_attack_count"]),
            "case transformations",
        )
        draw.rounded_rectangle(
            (90, 610, 1760, 890), radius=22, fill=PANEL, outline="#294766", width=2
        )
        draw.text((130, 650), "EXECUTED", font=font(24, True), fill=CYAN)
        wrapped(
            draw,
            f"{_count(metrics['micro_fixture_count'])} extracted public-diff semantics passed in Python, JavaScript and Rust.",
            (130, 700),
            660,
            30,
            WHITE,
            True,
        )
        draw.text((970, 650), "NOT CLAIMED", font=font(24, True), fill=AMBER)
        wrapped(
            draw,
            f"The {_count(metrics['case_count'])} upstream repositories were not cloned, "
            "repaired, or tested end-to-end. This is protocol evaluation, not "
            f"{_count(metrics['case_count'])} autonomous repair successes.",
            (970, 700),
            690,
            27,
            MUTED,
            True,
        )
        draw.text(
            (95, 930),
            f"Public source receipt: {'VERIFIED' if statuses['sources'] else 'PENDING'} / {metrics['case_count'] or 'N/A'} cases",
            font=font(24),
            fill=CYAN,
        )
    elif scene == 4:
        draw.text((90, 145), "Evidence before claims", font=font(62, True), fill=WHITE)
        rows = [
            (
                "Fault matrix",
                statuses["resilient"],
                f"{_count(metrics['trial_count'])} executable trials",
            ),
            (
                "Source verification",
                statuses["sources"],
                f"{metrics['case_count']} GitHub REST receipts",
            ),
            (
                "Micro-replays",
                statuses["micro"],
                f"{metrics['language_count']} language runtimes",
            ),
            (
                "Container isolation",
                statuses["isolation"],
                "network none / read-only / caps dropped",
            ),
            (
                "Clean wheel replay",
                evidence["clean_passed"],
                (
                    f"isolated replay passed for {evidence['clean_archive']}"
                    if evidence["clean_passed"]
                    else "pending; excluded from completion claim"
                ),
            ),
        ]
        for index, (name, passed, detail) in enumerate(rows):
            y = 280 + index * 137
            draw.rounded_rectangle(
                (90, y, 1760, y + 100), radius=18, fill=PANEL, outline="#294766", width=2
            )
            draw.text(
                (130, y + 27),
                "VERIFIED" if passed else "PENDING",
                font=font(22, True),
                fill=CYAN if passed else AMBER,
            )
            draw.text((370, y + 25), name, font=font(28, True), fill=WHITE)
            draw.text((925, y + 28), detail, font=font(23), fill=MUTED)
    elif scene == 5:
        draw.text(
            (90, 145), "Official AgentTeams evidence boundary", font=font(60, True), fill=WHITE
        )
        if agentteams_valid:
            draw.text((90, 300), "VALIDATED LIVE RUNTIME RECEIPT", font=font(39, True), fill=CYAN)
            wrapped(
                draw,
                "Official pinned runtime components, Manager/Worker orchestration trace and deny-by-default ACL probe are captured in artifacts/agentteams-live-evidence.json.",
                (95, 390),
                1450,
                34,
                WHITE,
            )
        else:
            draw.text((90, 300), "PENDING FINAL RUNTIME WIRING", font=font(39, True), fill=AMBER)
            wrapped(
                draw,
                "The official AgentTeams runtime receipt is not yet valid. This video does not claim completion, a live Manager/Worker trace, or role ACL proof until that artifact validates.",
                (95, 390),
                1450,
                34,
                WHITE,
            )
        draw.rounded_rectangle(
            (90, 650, 1760, 870), radius=24, fill=PANEL, outline="#294766", width=2
        )
        draw.text((130, 690), "ZERO-CREDENTIAL PATH", font=font(22, True), fill=CYAN)
        draw.text(
            (130, 745),
            "Deterministic local recovery and protocol evidence",
            font=font(30, True),
            fill=WHITE,
        )
        draw.text((1000, 690), "CLOUD BOUNDARY", font=font(22, True), fill=AMBER)
        wrapped(
            draw,
            "No cloud API call, external model network, or cost is claimed without a receipt.",
            (1000, 745),
            650,
            27,
            MUTED,
        )
    else:
        draw.text((90, 145), "Clone. Run. Inspect every receipt.", font=font(61, True), fill=WHITE)
        commands = evidence["commands"]
        draw.rounded_rectangle(
            (90, 280, 1560, 770), radius=24, fill="#050a12", outline="#2b4766", width=2
        )
        for index, command in enumerate(commands):
            draw.text(
                (135, 335 + index * 78),
                f"$ {command}",
                font=font(25, index == 0),
                fill=CYAN if index == 0 else WHITE,
            )
        draw.text(
            (95, 835),
            "Apache-2.0 / github.com/Oxygen56/remedyfabric",
            font=font(33, True),
            fill=CYAN,
        )
        draw.text(
            (95, 900),
            "Evidence: "
            + (
                "COMPLETE BEFORE HEAD FREEZE"
                if evidence_complete
                else "INCOMPLETE - unfinished evidence remains visible"
            ),
            font=font(27, True),
            fill=CYAN if evidence_complete else AMBER,
        )
    fade = min(1.0, local_time * 1.8)
    if fade < 1:
        image = Image.blend(Image.new("RGB", (WIDTH, HEIGHT), BG), image, fade)
    return image


def make_video(
    output: Path,
    preview: Path = DEFAULT_PREVIEW,
    *,
    allow_incomplete_preview: bool = False,
) -> dict[str, Any]:
    contract = build_presentation_contract(ROOT)
    require_presentation_render(
        ROOT,
        contract,
        [output, preview],
        allow_incomplete_preview=allow_incomplete_preview,
    )
    evidence = {
        "clean_passed": contract["statuses"]["clean"],
        "clean_archive": "evidence-bound wheel",
        "agentteams_valid": contract["statuses"]["agentteams"],
        "pre_freeze_evidence_complete": contract["statuses"]["evidence_complete"],
        "role_counts": contract["topology"]["recovery_role_counts"],
        "proposal_quorum": contract["topology"]["proposal_quorum"],
        "verifier_quorum": contract["topology"]["verifier_quorum"],
        "contract_metrics": contract["metrics"],
        "commands": contract["commands"],
        "statuses": contract["statuses"],
    }
    scene_seconds, scene_count = 7, 7
    total_frames = scene_seconds * scene_count * FPS
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="remedyfabric-champion-video-") as temporary:
        silent = Path(temporary) / "silent-video-only.mp4"
        subtitles = Path(temporary) / "captions.srt"
        captioned = Path(temporary) / "silent-captioned.mp4"
        writer = imageio_ffmpeg.write_frames(
            str(silent),
            (WIDTH, HEIGHT),
            fps=FPS,
            codec="libx264",
            quality=7,
            macro_block_size=2,
            output_params=[
                "-preset",
                "ultrafast",
                "-pix_fmt",
                "yuv420p",
                "-movflags",
                "+faststart",
            ],
        )
        writer.send(None)
        for frame_index in range(total_frames):
            elapsed = frame_index / FPS
            scene = min(scene_count - 1, int(elapsed / scene_seconds))
            frame = render_scene(
                scene,
                elapsed - scene * scene_seconds,
                frame_index / (total_frames - 1),
                evidence,
            )
            writer.send(frame.tobytes())
        writer.close()
        _write_srt(subtitles, contract)
        _mux_silent_captions(silent, subtitles, captioned, contract)
        # Exactly one H.264 video stream and one complete mov_text subtitle
        # stream are delivered. There is intentionally no audio stream and no
        # generated/system voice to license or redistribute.
        captioned.replace(output)
    preview.parent.mkdir(parents=True, exist_ok=True)
    preview_receipt = build_contact_sheet_from_video(output, preview, contract, root=ROOT)
    return {
        "output": str(output),
        "preview": str(preview),
        "seconds": scene_seconds * scene_count,
        "scene_count": scene_count,
        "agentteams_validated": evidence["agentteams_valid"],
        "clean_replay_passed": evidence["clean_passed"],
        "pre_freeze_evidence_complete": evidence["pre_freeze_evidence_complete"],
        "presentation_contract_sha256": contract["presentation_contract_sha256"],
        "caption_contract_sha256": caption_contract_sha256(contract),
        "preview_sha256": preview_receipt["sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--preview", type=Path, default=DEFAULT_PREVIEW)
    parser.add_argument("--allow-incomplete-preview", action="store_true")
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    preview = args.preview if args.preview.is_absolute() else ROOT / args.preview
    print(
        json.dumps(
            make_video(
                output,
                preview,
                allow_incomplete_preview=args.allow_incomplete_preview,
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
