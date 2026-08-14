#!/usr/bin/env python3
"""Recompute the final judge delivery from evidence and delivered bytes."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from remedyfabric.delivery_validation import (
    REPRODUCTION_COMMANDS,
    build_presentation_contract,
    caption_contract_sha256,
    inspect_delivery,
    inspect_font_license,
    validate_delivery_receipt,
)

ROOT = Path(__file__).resolve().parents[1]


def verify(*, visual_inspection_confirmed: bool) -> dict[str, object]:
    contract = build_presentation_contract(ROOT)
    delivery = inspect_delivery(ROOT, contract)
    fonts = inspect_font_license(ROOT)
    checks = {
        "evidence_bindings": set(contract["evidence_bindings"])
        == {
            "resilient",
            "model",
            "faultbench",
            "sources",
            "micro",
            "isolation",
            "clean",
            "agentteams",
        },
        "presentation_evidence_complete": contract["statuses"]["evidence_complete"] is True,
        "reproduction_commands": contract["command_targets_valid"] is True
        and tuple(contract["commands"]) == REPRODUCTION_COMMANDS,
        "font_license": fonts["passed"] is True,
        "pdf_structure": delivery["pdf"]["structure_passed"] is True,
        "pdf_text_contract": delivery["pdf"]["text_contract_passed"] is True,
        "video_structure": delivery["video"]["structure_passed"] is True,
        "video_caption_contract": delivery["video"]["caption_contract_passed"] is True,
        "preview_contact_sheet": delivery["preview"]["passed"] is True,
        "dashboard_self_contained": delivery["dashboard"]["structure_passed"] is True,
        "dashboard_text_contract": delivery["dashboard"]["text_contract_passed"] is True,
        "visual_inspection": visual_inspection_confirmed,
    }
    payload: dict[str, object] = {
        "schema_version": "remedyfabric.delivery-qa.v2",
        "verified_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "presentation_contract_sha256": contract["presentation_contract_sha256"],
        "caption_contract_sha256": caption_contract_sha256(contract),
        "evidence_bindings": contract["evidence_bindings"],
        "passed": all(checks.values()),
        "checks": checks,
        "fonts": fonts,
        **delivery,
        "claim_boundary": (
            "Structural and semantic checks were recomputed from current bytes and evidence. "
            "The MP4 has exactly one H.264 video stream, one complete English subtitle stream, "
            "and zero audio streams. Visual inspection means every PDF page and every scene "
            "midpoint contact-sheet tile was reviewed; it is not proof of playback on every device."
        ),
    }
    # Reuse the same validator consumed by the manifest, gate, and package.
    failures = validate_delivery_receipt(payload, ROOT)
    if failures:
        payload["passed"] = False
        payload["validation_failures"] = failures
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/delivery-qa.json"))
    parser.add_argument(
        "--visual-inspection-confirmed",
        action="store_true",
        help="Confirm review of every PDF page and all seven video scene midpoint tiles.",
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    payload = verify(visual_inspection_confirmed=args.visual_inspection_confirmed)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "passed": payload["passed"]}, indent=2))
    return 0 if payload["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
