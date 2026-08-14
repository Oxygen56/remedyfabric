#!/usr/bin/env python3
"""Fail-closed checker for the frozen RemedyFabric champion evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from remedyfabric.agentteams_evidence import live_evidence_is_valid
from remedyfabric.delivery_validation import validate_delivery_receipt
from remedyfabric.evidence_validation import validate_core_evidence
from remedyfabric.release_integrity import clean_replay_current

REQUIRED_ARTIFACTS = {
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
    "artifacts/agentteams-live-evidence.json",
    "artifacts/agentteams-runtime-blocked.json",
    "artifacts/benchmark.json",
    "artifacts/clean-release-ci.zip",
    "artifacts/clean-replay.json",
    "artifacts/container-isolation.json",
    "artifacts/dashboard.html",
    "artifacts/delivery-qa.json",
    "artifacts/faultbench-micro-replays.json",
    "artifacts/faultbench-results.json",
    "artifacts/faultbench-source-verification.json",
    "artifacts/public-ci.json",
    "artifacts/quorum-model.json",
    "artifacts/remedyfabric-champion-demo.mp4",
    "artifacts/resilient-matrix.json",
    "artifacts/video-preview.jpg",
    "output/pdf/remedyfabric-goai-agent-infra-champion.pdf",
}


def _read(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected JSON object: {path}")
    return payload


def evaluate(contract: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    required = contract["required_gates"]

    protocol = evidence.get("protocol", {})
    protocol_required = required["protocol"]
    numeric_protocol = {
        "single_fault_unsafe_release_rate": "single_fault_unsafe_release_rate_max",
        "single_fault_relative_recovery_rate": "single_fault_relative_recovery_rate_min",
        "beyond_boundary_fail_closed_rate": "beyond_boundary_fail_closed_rate_min",
        "exhaustive_states": "exhaustive_states_min",
        "executable_trials": "executable_trials_min",
    }
    for observed_key, requirement_key in numeric_protocol.items():
        if observed_key not in protocol:
            failures.append(f"protocol.{observed_key}: missing")
            continue
        observed = protocol[observed_key]
        expected = protocol_required[requirement_key]
        if requirement_key.endswith("_max") and observed > expected:
            failures.append(f"protocol.{observed_key}: {observed} > {expected}")
        if requirement_key.endswith("_min") and observed < expected:
            failures.append(f"protocol.{observed_key}: {observed} < {expected}")
    if protocol.get("single_worker_can_authorize_release") is not False:
        failures.append("protocol.single_worker_can_authorize_release: must be false")

    bench = evidence.get("faultbench_oss", {})
    bench_required = required["faultbench_oss"]
    for observed_key, requirement_key in {
        "cases": "cases_min",
        "repositories": "repositories_min",
        "languages": "languages_min",
        "fault_classes": "fault_classes_min",
        "provenance_coverage": "provenance_coverage_min",
        "micro_replays": "micro_replays_min",
    }.items():
        if observed_key not in bench:
            failures.append(f"faultbench_oss.{observed_key}: missing")
        elif bench[observed_key] < bench_required[requirement_key]:
            failures.append(
                f"faultbench_oss.{observed_key}: {bench[observed_key]} < "
                f"{bench_required[requirement_key]}"
            )
    if bench.get("negative_controls") is not True:
        failures.append("faultbench_oss.negative_controls: must be true")

    for group in ("agentteams", "reproducibility", "judge_delivery"):
        observed_group = evidence.get(group, {})
        for requirement_key, required_value in required[group].items():
            observed_key = requirement_key.removesuffix("_required")
            if required_value is True and observed_group.get(observed_key) is not True:
                failures.append(f"{group}.{observed_key}: must be true")

    return failures


def validate_manifest_integrity(evidence: dict[str, Any], root: Path) -> list[str]:
    """Verify the manifest digest and every bound artifact before threshold evaluation."""

    failures: list[str] = []
    expected_digest = evidence.get("manifest_evidence_digest")
    unsigned = dict(evidence)
    unsigned.pop("manifest_evidence_digest", None)
    observed_digest = hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if expected_digest != observed_digest:
        failures.append("manifest_evidence_digest: mismatch")

    artifacts = evidence.get("artifacts", {})
    if not isinstance(artifacts, dict):
        return [*failures, "artifacts: missing or malformed"]
    missing = sorted(REQUIRED_ARTIFACTS.difference(artifacts))
    failures.extend(f"artifacts.{relative}: required binding missing" for relative in missing)
    for relative, receipt in artifacts.items():
        pure = PurePosixPath(str(relative))
        if pure.is_absolute() or ".." in pure.parts:
            failures.append(f"artifacts.{relative}: unsafe path")
            continue
        if not isinstance(receipt, dict):
            failures.append(f"artifacts.{relative}: malformed receipt")
            continue
        target = root / pure
        if not target.is_file():
            failures.append(f"artifacts.{relative}: file missing")
            continue
        content = target.read_bytes()
        if receipt.get("size_bytes") != len(content):
            failures.append(f"artifacts.{relative}: size mismatch")
        if receipt.get("sha256") != hashlib.sha256(content).hexdigest():
            failures.append(f"artifacts.{relative}: sha256 mismatch")
    return failures


def validate_runtime_semantics(root: Path) -> list[str]:
    """Recompute semantic truth from receipts instead of trusting manifest booleans."""

    failures: list[str] = []

    def load(relative: str) -> dict[str, Any]:
        path = root / relative
        if not path.is_file():
            failures.append(f"semantic.{relative}: missing")
            return {}
        return _read(path)

    resilient = load("artifacts/resilient-matrix.json")
    model = load("artifacts/quorum-model.json")
    faultbench = load("artifacts/faultbench-results.json")
    sources = load("artifacts/faultbench-source-verification.json")
    micro = load("artifacts/faultbench-micro-replays.json")
    isolation = load("artifacts/container-isolation.json")
    if all((resilient, model, faultbench, sources, micro, isolation)):
        failures.extend(
            f"semantic.{failure}"
            for failure in validate_core_evidence(
                root=root,
                resilient=resilient,
                model=model,
                faultbench=faultbench,
                sources=sources,
                micro=micro,
                isolation=isolation,
            )
        )

    agentteams = load("artifacts/agentteams-live-evidence.json")
    if agentteams and not live_evidence_is_valid(agentteams):
        failures.append("semantic.agentteams-live-evidence: strict validation failed")

    clean = load("artifacts/clean-replay.json")
    if not clean_replay_current(clean, root):
        failures.append("semantic.clean-replay: current release integrity contract failed")
    delivery = load("artifacts/delivery-qa.json")
    if delivery:
        failures.extend(
            f"semantic.delivery: {failure}" for failure in validate_delivery_receipt(delivery, root)
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default="competition/champion-contract.json")
    parser.add_argument("--evidence", default="artifacts/champion-evidence.json")
    parser.add_argument("--output", default="artifacts/champion-gate.json")
    args = parser.parse_args()
    contract_path = Path(args.contract)
    evidence_path = Path(args.evidence)
    output_path = Path(args.output)
    failures: list[str]
    if not evidence_path.exists():
        failures = [f"evidence manifest missing: {evidence_path}"]
    else:
        evidence = _read(evidence_path)
        failures = [
            *validate_manifest_integrity(evidence, evidence_path.resolve().parents[1]),
            *validate_runtime_semantics(evidence_path.resolve().parents[1]),
            *evaluate(_read(contract_path), evidence),
        ]
    result = {
        "schema_version": "1.0",
        "status": "ready" if not failures else "not_ready",
        "failures": failures,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
