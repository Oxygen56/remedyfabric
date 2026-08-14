from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.champion_gate import (
    REQUIRED_ARTIFACTS,
    evaluate,
    validate_manifest_integrity,
    validate_runtime_semantics,
)

ROOT = Path(__file__).resolve().parents[1]


def passing_evidence() -> dict[str, object]:
    return {
        "protocol": {
            "single_fault_unsafe_release_rate": 0.0,
            "single_fault_relative_recovery_rate": 0.95,
            "beyond_boundary_fail_closed_rate": 1.0,
            "single_worker_can_authorize_release": False,
            "exhaustive_states": 512,
            "executable_trials": 20,
        },
        "faultbench_oss": {
            "cases": 30,
            "repositories": 6,
            "languages": 3,
            "fault_classes": 8,
            "provenance_coverage": 1.0,
            "negative_controls": True,
            "micro_replays": 3,
        },
        "agentteams": {
            "official_runtime": True,
            "manager_worker_trace": True,
            "complete_multi_agent_loop": True,
            "role_acl_evidence": True,
            "official_cloud_skill_invocation": True,
            "structured_shared_context": True,
            "append_only_evidence_trace": True,
            "independent_release_authority": True,
            "bounded_claim": True,
            "official_source_pinned": True,
        },
        "reproducibility": {
            "core_evidence_semantically_valid": True,
            "clean_environment_run": True,
            "unit_tests": True,
            "benchmark_rerun": True,
            "package_integrity": True,
            "public_ci": True,
            "container_isolation": True,
        },
        "judge_delivery": {
            "scorecard": True,
            "dashboard": True,
            "proposal_pdf": True,
            "demo_video": True,
            "disclosure": True,
        },
    }


class ChampionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(
            (ROOT / "competition/champion-contract.json").read_text(encoding="utf-8")
        )

    def test_complete_evidence_passes(self) -> None:
        self.assertEqual(evaluate(self.contract, passing_evidence()), [])

    def test_judge_facing_support_files_are_required_bindings(self) -> None:
        self.assertTrue(
            {
                "artifacts/benchmark.json",
                "artifacts/agentteams-runtime-blocked.json",
                "artifacts/clean-release-ci.zip",
                "agentteams/official-runtime-images.lock.json",
            }.issubset(REQUIRED_ARTIFACTS)
        )

    def test_single_worker_authority_fails_closed(self) -> None:
        evidence = passing_evidence()
        evidence["protocol"]["single_worker_can_authorize_release"] = True  # type: ignore[index]
        failures = evaluate(self.contract, evidence)
        self.assertIn("protocol.single_worker_can_authorize_release: must be false", failures)

    def test_missing_runtime_evidence_fails(self) -> None:
        evidence = passing_evidence()
        del evidence["agentteams"]["manager_worker_trace"]  # type: ignore[index]
        failures = evaluate(self.contract, evidence)
        self.assertIn("agentteams.manager_worker_trace: must be true", failures)

    def test_manifest_integrity_detects_changed_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.json"
            artifact.write_text('{"value":1}\n', encoding="utf-8")
            content = artifact.read_bytes()
            evidence = {
                "artifacts": {
                    "artifact.json": {
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size_bytes": len(content),
                    }
                }
            }
            evidence["manifest_evidence_digest"] = hashlib.sha256(
                json.dumps(
                    evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
            artifact.write_text('{"value":2}\n', encoding="utf-8")
            failures = validate_manifest_integrity(evidence, root)
            self.assertIn("artifacts.artifact.json: sha256 mismatch", failures)

    def test_runtime_semantics_delegates_clean_replay_to_current_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = {"fixture": True}
            for relative in (
                "artifacts/resilient-matrix.json",
                "artifacts/quorum-model.json",
                "artifacts/faultbench-results.json",
                "artifacts/faultbench-source-verification.json",
                "artifacts/faultbench-micro-replays.json",
                "artifacts/container-isolation.json",
                "artifacts/agentteams-live-evidence.json",
                "artifacts/clean-replay.json",
                "artifacts/delivery-qa.json",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = {} if relative == "artifacts/clean-replay.json" else fixture
                path.write_text(json.dumps(payload), encoding="utf-8")

            with (
                patch("scripts.champion_gate.validate_core_evidence", return_value=[]),
                patch("scripts.champion_gate.live_evidence_is_valid", return_value=True),
                patch("scripts.champion_gate.validate_delivery_receipt", return_value=[]),
                patch(
                    "scripts.champion_gate.clean_replay_current",
                    return_value=False,
                ) as validator,
            ):
                failures = validate_runtime_semantics(root)

            validator.assert_called_once_with({}, root)
            self.assertEqual(
                failures,
                ["semantic.clean-replay: current release integrity contract failed"],
            )


if __name__ == "__main__":
    unittest.main()
