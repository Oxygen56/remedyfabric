#!/usr/bin/env python3
"""Assemble immutable judge-facing evidence into the fail-closed champion manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for import_root in (ROOT / "src", ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from remedyfabric.agentteams_evidence import live_evidence_is_valid
from remedyfabric.delivery_validation import validate_delivery_receipt
from remedyfabric.evidence_validation import validate_core_evidence
from remedyfabric.public_ci_validation import validate_public_ci_receipt
from remedyfabric.release_integrity import clean_replay_current


def _load(relative: str, *, required: bool = True) -> dict[str, Any] | None:
    path = ROOT / relative
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected JSON object: {path}")
    return payload


def _sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def _profile(bench: dict[str, Any], name: str) -> dict[str, Any]:
    return next(profile for profile in bench["profiles"] if profile["profile"] == name)


def _public_ci_passed(receipt: dict[str, Any] | None) -> bool:
    if not receipt:
        return False
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    return not validate_public_ci_receipt(receipt, head, live=True)


def _clean_replay_current(receipt: dict[str, Any] | None) -> bool:
    """Backward-compatible script helper used by focused gate tests."""

    return clean_replay_current(receipt, ROOT)


def _delivery_checks() -> dict[str, bool]:
    scorecard = ROOT / "docs/GOAI_SCORECARD.md"
    dashboard = ROOT / "artifacts/dashboard.html"
    proposal = ROOT / "output/pdf/remedyfabric-goai-agent-infra-champion.pdf"
    video = ROOT / "artifacts/remedyfabric-champion-demo.mp4"
    disclosure = ROOT / "docs/DISCLOSURE.md"
    qa = _load("artifacts/delivery-qa.json", required=False)
    qa_passed = bool(qa and not validate_delivery_receipt(qa, ROOT))
    scorecard_text = scorecard.read_text(encoding="utf-8") if scorecard.exists() else ""
    dashboard_bytes = dashboard.read_bytes() if dashboard.exists() else b""
    proposal_bytes = proposal.read_bytes() if proposal.exists() else b""
    video_bytes = video.read_bytes() if video.exists() else b""
    disclosure_text = disclosure.read_text(encoding="utf-8") if disclosure.exists() else ""
    qa_dashboard = bool(
        qa_passed
        and qa.get("dashboard", {}).get("sha256") == hashlib.sha256(dashboard_bytes).hexdigest()
    )
    qa_proposal = bool(
        qa_passed and qa.get("pdf", {}).get("sha256") == hashlib.sha256(proposal_bytes).hexdigest()
    )
    qa_video = bool(
        qa_passed and qa.get("video", {}).get("sha256") == hashlib.sha256(video_bytes).hexdigest()
    )
    return {
        "scorecard": len(scorecard_text) >= 1_000 and "25" in scorecard_text,
        "dashboard": qa_dashboard
        and len(dashboard_bytes) >= 5_000
        and b"RemedyFabric" in dashboard_bytes,
        "proposal_pdf": qa_proposal
        and len(proposal_bytes) >= 50_000
        and proposal_bytes.startswith(b"%PDF-"),
        "demo_video": qa_video and len(video_bytes) >= 500_000 and b"ftyp" in video_bytes[:64],
        "disclosure": len(disclosure_text) >= 1_000
        and "Codex" in disclosure_text
        and "AgentTeams" in disclosure_text,
    }


def build_manifest(*, judge_delivery_ready: bool) -> dict[str, Any]:
    resilient = _load("artifacts/resilient-matrix.json")
    model = _load("artifacts/quorum-model.json")
    faultbench = _load("artifacts/faultbench-results.json")
    sources = _load("artifacts/faultbench-source-verification.json")
    micro = _load("artifacts/faultbench-micro-replays.json")
    isolation = _load("artifacts/container-isolation.json")
    clean = _load("artifacts/clean-replay.json", required=False)
    agentteams = _load("artifacts/agentteams-live-evidence.json", required=False)
    public_ci = _load("artifacts/public-ci.json", required=False)
    semantic_failures = validate_core_evidence(
        root=ROOT,
        resilient=resilient,
        model=model,
        faultbench=faultbench,
        sources=sources,
        micro=micro,
        isolation=isolation,
    )
    if semantic_failures:
        raise RuntimeError(
            "core evidence semantic validation failed: " + ", ".join(semantic_failures)
        )
    champion = _profile(faultbench, "champion-quorum")
    weaker = [_profile(faultbench, name) for name in ("single-agent", "simple-majority", "v0.1")]

    source_status = sources.get("status") == "verified"
    provenance = 1.0 if source_status else 0.0
    agentteams_valid = live_evidence_is_valid(agentteams)
    clean_current = clean_replay_current(clean, ROOT)
    delivery_checks = _delivery_checks()
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "project": "RemedyFabric",
        "track": "GOAI 2026 Agent Infra",
        "winning_claim": (
            "Safe recovery with one Byzantine-like Worker among three; fail closed for the "
            "enumerated cases beyond that boundary."
        ),
        "protocol": {
            "single_fault_unsafe_release_rate": resilient["metrics"][
                "single_worker_unsafe_releases"
            ]
            / resilient["metrics"]["single_worker_trials"],
            "single_fault_relative_recovery_rate": resilient["metrics"][
                "single_worker_relative_recovery_vs_baseline"
            ],
            "beyond_boundary_fail_closed_rate": resilient["metrics"][
                "tested_out_of_boundary_fail_closed_rate"
            ],
            "single_worker_can_authorize_release": not model["properties"][
                "single_worker_cannot_authorize"
            ]["holds"],
            "exhaustive_states": model["checked_decisions"],
            "executable_trials": resilient["metrics"]["trial_count"],
            "raw_evidence": "artifacts/resilient-matrix.json",
            "model_evidence": "artifacts/quorum-model.json",
        },
        "faultbench_oss": {
            "cases": faultbench["case_count"],
            "repositories": faultbench["repository_count"],
            "languages": faultbench["language_count"],
            "fault_classes": faultbench["fault_attack_count"],
            "provenance_coverage": provenance,
            "negative_controls": any(profile["unsafe_release_rate"] > 0 for profile in weaker),
            "champion_single_fault_safe_recovery_rate": champion["single_fault_safe_recovery_rate"],
            "champion_unsafe_release_rate": champion["unsafe_release_rate"],
            "champion_overflow_containment_rate": champion["overflow_containment_rate"],
            "micro_replay_status": micro.get("status"),
            "micro_replay_count": micro.get("fixture_count"),
            "micro_replays": micro.get("fixture_count") if micro.get("status") == "passed" else 0,
            "corpus_boundary": faultbench["claims_boundary"],
        },
        "agentteams": {
            "official_runtime": agentteams_valid,
            "manager_worker_trace": agentteams_valid,
            "complete_multi_agent_loop": agentteams_valid,
            "role_acl_evidence": agentteams_valid,
            "official_cloud_skill_invocation": agentteams_valid,
            "structured_shared_context": agentteams_valid,
            "append_only_evidence_trace": agentteams_valid,
            "independent_release_authority": agentteams_valid,
            "bounded_claim": bool(agentteams and agentteams.get("claim_boundary")),
            "official_source_pinned": agentteams_valid,
            "evidence": "artifacts/agentteams-live-evidence.json",
        },
        "reproducibility": {
            "core_evidence_semantically_valid": not semantic_failures,
            "clean_environment_run": clean_current,
            "unit_tests": clean_current,
            "benchmark_rerun": clean_current,
            "package_integrity": clean_current,
            "public_ci": _public_ci_passed(public_ci),
            "container_isolation": bool(isolation.get("passed")),
        },
        "judge_delivery": {
            name: judge_delivery_ready and passed for name, passed in delivery_checks.items()
        },
        "judge_delivery_checks": delivery_checks,
        "artifacts": {},
        "claim_boundaries": [
            "The executable matrix covers a finite one-Worker Byzantine-like model, not general BFT.",
            (
                "The 30-case OSS corpus evaluates protocol messages; only three extracted "
                "semantics were executed, not complete upstream repositories."
            ),
            (
                "Passing the gate is not production reliability evidence, third-party "
                "certification, or a guarantee of competition rank."
            ),
        ],
    }
    tracked = (
        ".github/workflows/ci.yml",
        "LICENSE",
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "agentteams/official-alibaba-cloud-skill.lock.json",
        "agentteams/official-runtime-images.lock.json",
        "agentteams/remedyfabric-live-local.yaml",
        "agentteams/remedyfabric-team.yaml",
        "competition.yaml",
        "competition/champion-contract.json",
        "docs/AGENTTEAMS_LIVE_RUN.md",
        "docs/ARCHITECTURE.md",
        "docs/CHAMPION_CONTRACT.md",
        "docs/DISCLOSURE.md",
        "docs/GOAI_SCORECARD.md",
        "docs/JUDGE_GUIDE.md",
        "docs/SECURITY_THREAT_MODEL.md",
        "site/tests/rendered-html.test.mjs",
        "skills/remedyfabric-recovery/SKILL.md",
        "submission/final-submission.zh.md",
        "artifacts/agentteams-runtime-blocked.json",
        "artifacts/benchmark.json",
        "artifacts/clean-release-ci.zip",
        "artifacts/resilient-matrix.json",
        "artifacts/quorum-model.json",
        "artifacts/faultbench-results.json",
        "artifacts/faultbench-source-verification.json",
        "artifacts/faultbench-micro-replays.json",
        "artifacts/container-isolation.json",
        "artifacts/clean-replay.json",
        "artifacts/agentteams-live-evidence.json",
        "artifacts/public-ci.json",
        "artifacts/delivery-qa.json",
        "artifacts/dashboard.html",
        "artifacts/remedyfabric-champion-demo.mp4",
        "artifacts/video-preview.jpg",
        "output/pdf/remedyfabric-goai-agent-infra-champion.pdf",
    )
    manifest["artifacts"] = {
        relative: {"sha256": _sha256(relative), "size_bytes": (ROOT / relative).stat().st_size}
        for relative in tracked
        if (ROOT / relative).exists()
    }
    manifest["manifest_evidence_digest"] = hashlib.sha256(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/champion-evidence.json"))
    parser.add_argument("--judge-delivery-ready", action="store_true")
    args = parser.parse_args()
    output = ROOT / args.output if not args.output.is_absolute() else args.output
    manifest = build_manifest(judge_delivery_ready=args.judge_delivery_ready)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "digest": manifest["manifest_evidence_digest"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
