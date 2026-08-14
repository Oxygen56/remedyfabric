"""Strict pre-freeze evidence completeness used by judge-facing renderers.

Presentation files are themselves later bound by delivery QA and the champion
manifest, so renderers cannot truthfully assert that their own final hashes or
the commit containing them already passed public CI.  This helper revalidates
every gate available before the repository HEAD is frozen.  Public-CI and
judge-delivery bindings remain mandatory in the post-HEAD machine gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for import_root in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from scripts.build_champion_evidence import ROOT, build_manifest
from scripts.champion_gate import evaluate


def presentation_failures(root: Path = ROOT) -> list[str]:
    if root != ROOT:
        raise ValueError("presentation readiness is bound to the repository root")
    try:
        manifest = build_manifest(judge_delivery_ready=False)
        contract = json.loads(
            (root / "competition/champion-contract.json").read_text(encoding="utf-8")
        )
    except (FileNotFoundError, KeyError, RuntimeError, TypeError, ValueError) as error:
        return [f"pre-delivery validation error: {error}"]
    post_head_only = ("judge_delivery.", "reproducibility.public_ci:")
    return [
        failure
        for failure in evaluate(contract, manifest)
        if not failure.startswith(post_head_only)
    ]


def presentation_ready(root: Path = ROOT) -> bool:
    return not presentation_failures(root)


__all__ = ["presentation_failures", "presentation_ready"]
