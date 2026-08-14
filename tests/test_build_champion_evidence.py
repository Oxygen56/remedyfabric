from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.build_champion_evidence import _clean_replay_current, build_manifest


class ChampionEvidenceBuilderTests(unittest.TestCase):
    def test_current_mechanism_evidence_is_derived_from_receipts(self) -> None:
        manifest = build_manifest(judge_delivery_ready=False)
        self.assertEqual(manifest["protocol"]["single_fault_unsafe_release_rate"], 0.0)
        self.assertEqual(manifest["protocol"]["single_fault_relative_recovery_rate"], 1.0)
        self.assertFalse(manifest["protocol"]["single_worker_can_authorize_release"])
        self.assertEqual(manifest["faultbench_oss"]["provenance_coverage"], 1.0)
        self.assertTrue(manifest["faultbench_oss"]["negative_controls"])
        self.assertEqual(manifest["faultbench_oss"]["micro_replays"], 3)
        self.assertEqual(manifest["protocol"]["executable_trials"], 22)

    def test_judge_delivery_is_never_inferred_from_unrelated_artifacts(self) -> None:
        manifest = build_manifest(judge_delivery_ready=False)
        self.assertFalse(any(manifest["judge_delivery"].values()))

    def test_judge_facing_support_files_are_byte_bound(self) -> None:
        manifest = build_manifest(judge_delivery_ready=False)
        self.assertIn("artifacts/benchmark.json", manifest["artifacts"])
        self.assertIn("artifacts/agentteams-runtime-blocked.json", manifest["artifacts"])
        self.assertIn("agentteams/official-runtime-images.lock.json", manifest["artifacts"])

    def test_old_package_version_cannot_satisfy_clean_replay_gate(self) -> None:
        receipt = {
            "passed": True,
            "project_version": "0.1.0",
            "source_tree_digest": "a" * 64,
            "source_tree_unchanged_after_build": True,
            "archives": [
                {"name": "remedyfabric-0.1.0-py3-none-any.whl", "member_paths_safe": True},
                {"name": "remedyfabric-0.1.0.tar.gz", "member_paths_safe": True},
            ],
        }
        with (
            patch("remedyfabric.release_integrity.project_version", return_value="0.2.0"),
            patch("remedyfabric.release_integrity.source_tree_digest", return_value="a" * 64),
        ):
            self.assertFalse(_clean_replay_current(receipt))


if __name__ == "__main__":
    unittest.main()
