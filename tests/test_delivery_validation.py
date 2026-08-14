from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from itertools import pairwise
from pathlib import Path
from unittest.mock import patch

from remedyfabric import delivery_validation as delivery
from remedyfabric.release_integrity import CLEAN_REPLAY_EXTERNAL_TESTS, source_tree_digest

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeliveryValidationTests(unittest.TestCase):
    def _valid_clean_receipt(self, root: Path) -> dict[str, object]:
        (root / "dist").mkdir(exist_ok=True)
        archives = []
        for name in (
            "remedyfabric-0.2.0-py3-none-any.whl",
            "remedyfabric-0.2.0.tar.gz",
        ):
            path = root / "dist" / name
            path.write_bytes(name.encode())
            archives.append(
                {
                    "name": name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                    "member_count": 1,
                    "member_paths_safe": True,
                }
            )
        executed = 93
        return {
            "passed": True,
            "project_version": "0.2.0",
            "source_tree_digest": source_tree_digest(root),
            "source_tree_unchanged_after_build": True,
            "unexpected_dist_members": [],
            "package_build": {
                "returncode": 0,
                "command": [
                    "uv",
                    "build",
                    "--offline",
                    "--clear",
                    "--no-create-gitignore",
                    "--out-dir",
                    "dist",
                    ".",
                ],
                "duration_ms": 1.0,
            },
            "archives": archives,
            "clean_environment": {
                "base_image": {
                    "tag": "python:3.12-slim",
                    "resolved_reference": "python@sha256:" + "a" * 64,
                    "image_id": "sha256:" + "b" * 64,
                    "platform": "linux/amd64",
                },
                "container_image_build_network": "none",
                "runtime_network": "none",
                "rootfs_read_only": True,
                "image_build": {
                    "returncode": 0,
                    "command": ["docker", "build", "--network", "none", "."],
                    "duration_ms": 2.0,
                },
                "replay": {
                    "returncode": 0,
                    "command": [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "--pids-limit",
                        "128",
                        "--memory",
                        "512m",
                        "--cpus",
                        "1.0",
                        "fixture",
                        "python",
                        "/clean_replay_entrypoint.py",
                    ],
                    "duration_ms": 3.0,
                },
                "tests_run": executed,
                "tests_skipped": 0,
                "test_suite": {
                    "kind": "pure-python-offline",
                    "passed": True,
                    "nonce": "d" * 32,
                    "missing_expected_exclusions": [],
                    "discovered_tests": executed + len(CLEAN_REPLAY_EXTERNAL_TESTS),
                    "executed_tests": executed,
                    "skipped_tests": 0,
                    "selected_test_ids_sha256": "c" * 64,
                    "excluded_external_tests": CLEAN_REPLAY_EXTERNAL_TESTS,
                },
                "semantic_evidence_validated": True,
                "semantic_replays": {
                    "remedybench": True,
                    "resilient_matrix": True,
                    "quorum_model": True,
                    "faultbench": True,
                },
                "external_runtime_boundaries": {
                    "node_rust_micro_replays": "not executed here",
                    "nested_docker_isolation": "not executed here",
                    "git_repository_fixtures": "not executed here",
                    "delivery_inspection": "not executed here",
                },
            },
        }

    def _presentation_fixture(self, root: Path) -> dict[str, object]:
        (root / "pyproject.toml").write_text(
            '[project]\nname = "remedyfabric"\nversion = "0.2.0"\n', encoding="utf-8"
        )
        (root / "faultbench").mkdir()
        (root / "faultbench/cases.json").write_text('{"cases": []}\n', encoding="utf-8")
        for relative in delivery.EVIDENCE_PATHS.values():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative != delivery.EVIDENCE_PATHS["clean"]:
                path.write_text("{}\n", encoding="utf-8")
        receipt = self._valid_clean_receipt(root)
        (root / delivery.EVIDENCE_PATHS["clean"]).write_text(json.dumps(receipt), encoding="utf-8")
        return receipt

    def test_presentation_contract_uses_stable_strict_clean_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self._presentation_fixture(root)
            with (
                patch.object(delivery, "_validator_passes", return_value=True),
                patch(
                    "remedyfabric.agentteams_evidence.live_evidence_is_valid",
                    return_value=True,
                ),
            ):
                first_contract = delivery.build_presentation_contract(root)
                second = copy.deepcopy(first)
                second["package_build"]["duration_ms"] = 101.0  # type: ignore[index]
                environment = second["clean_environment"]  # type: ignore[assignment]
                environment["test_suite"]["nonce"] = "e" * 32  # type: ignore[index]
                environment["replay"]["duration_ms"] = 102.0  # type: ignore[index]
                environment["base_image"] = {  # type: ignore[index]
                    "tag": "python:3.12-slim",
                    "resolved_reference": "python@sha256:" + "f" * 64,
                    "image_id": "sha256:" + "0" * 64,
                    "platform": "linux/arm64",
                }
                (root / delivery.EVIDENCE_PATHS["clean"]).write_text(
                    json.dumps(second), encoding="utf-8"
                )
                second_contract = delivery.build_presentation_contract(root)
                self.assertEqual(
                    first_contract["presentation_contract_sha256"],
                    second_contract["presentation_contract_sha256"],
                )
                self.assertNotIn("size_bytes", first_contract["evidence_bindings"]["clean"])
                self.assertEqual(
                    first_contract["evidence_bindings"]["clean"]["binding"],
                    "strict-semantic-projection-v1",
                )

                second["clean_environment"]["test_suite"][  # type: ignore[index]
                    "selected_test_ids_sha256"
                ] = "9" * 64
                (root / delivery.EVIDENCE_PATHS["clean"]).write_text(
                    json.dumps(second), encoding="utf-8"
                )
                changed_contract = delivery.build_presentation_contract(root)
                self.assertNotEqual(
                    first_contract["presentation_contract_sha256"],
                    changed_contract["presentation_contract_sha256"],
                )

    def test_presentation_contract_derives_current_topology_and_metrics(self) -> None:
        contract = delivery.build_presentation_contract(ROOT)
        self.assertEqual(
            contract["topology"]["recovery_role_counts"],
            {
                "challenger": 1,
                "governor": 1,
                "release-manager": 1,
                "verifier": 2,
                "worker": 3,
            },
        )
        self.assertEqual(contract["topology"]["proposal_quorum"], 2)
        self.assertEqual(contract["topology"]["verifier_quorum"], 2)
        self.assertEqual(contract["metrics"]["trial_count"], 22)
        self.assertEqual(contract["metrics"]["faultbench_single_fault_cases"], 23)
        self.assertEqual(contract["metrics"]["faultbench_overflow_cases"], 7)
        model = json.loads((ROOT / "artifacts/quorum-model.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["metrics"]["checked_decisions"], model["checked_decisions"])
        self.assertTrue(contract["statuses"]["core"])
        self.assertEqual(
            contract["statuses"]["evidence_complete"],
            contract["statuses"]["core"]
            and contract["statuses"]["clean"]
            and contract["statuses"]["agentteams"],
        )

    def test_font_license_and_pinned_files_are_verified(self) -> None:
        receipt = delivery.inspect_font_license(ROOT)
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["sha256"], delivery.PINNED_FONT_SHA256)
        self.assertEqual(receipt["license"], "SIL Open Font License 1.1")

    def test_caption_contract_is_complete_and_covers_exact_duration(self) -> None:
        contract = delivery.build_presentation_contract(ROOT)
        cues = delivery.video_caption_cues(contract)
        self.assertEqual(len(cues), 7)
        self.assertEqual(cues[0]["start_seconds"], 0)
        self.assertEqual(cues[-1]["end_seconds"], 49)
        for left, right in pairwise(cues):
            self.assertEqual(left["end_seconds"], right["start_seconds"])
        payload = delivery.expected_subtitle_payload(contract)
        self.assertEqual(len(payload), 7)
        self.assertTrue(all(value.strip() for value in payload))
        self.assertIn("remedyfabric resilient", payload[-1])

    @unittest.skipUnless(shutil.which("ffprobe") and shutil.which("ffmpeg"), "requires FFmpeg")
    def test_caption_mux_removes_audio_and_binds_complete_subtitles(self) -> None:
        source = ROOT / "artifacts/remedyfabric-champion-demo.mp4"
        if not source.is_file():
            self.skipTest("demo source is not present")
        module = _load_script("make_demo_video_test", "scripts/make_demo_video.py")
        contract = delivery.build_presentation_contract(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            subtitles = Path(temporary) / "captions.srt"
            output = Path(temporary) / "captioned.mp4"
            preview = Path(temporary) / "contact.jpg"
            module._write_srt(subtitles, contract)
            module._mux_silent_captions(source, subtitles, output, contract)
            observed = delivery.inspect_video(output, contract)
            delivery.build_contact_sheet_from_video(output, preview, contract, root=ROOT)
            preview_observed = delivery.inspect_preview(preview, output, contract)
        self.assertFalse(observed["audio_present"])
        self.assertEqual(observed["audio_stream_count"], 0)
        self.assertEqual(observed["subtitle_stream_count"], 1)
        self.assertEqual(observed["subtitle_cue_count"], 7)
        self.assertTrue(observed["caption_contract_passed"])
        self.assertTrue(observed["structure_passed"])
        self.assertTrue(preview_observed["contact_sheet_matches_video"])
        self.assertTrue(preview_observed["metadata_matches_contract"])
        self.assertTrue(preview_observed["passed"])

    def test_delivery_validator_rejects_false_passed_flag_and_stale_contract(self) -> None:
        contract = {
            "presentation_contract_sha256": "a" * 64,
            "evidence_bindings": {name: {} for name in delivery.EVIDENCE_PATHS},
            "statuses": {"evidence_complete": True},
        }
        font = {"passed": True}
        observed = {
            "pdf": {"structure_passed": True, "text_contract_passed": True},
            "video": {"structure_passed": True, "caption_contract_passed": True},
            "preview": {"passed": True},
            "dashboard": {"structure_passed": True, "text_contract_passed": True},
        }
        receipt = {
            "schema_version": "remedyfabric.delivery-qa.v2",
            "presentation_contract_sha256": "b" * 64,
            "caption_contract_sha256": "c" * 64,
            "evidence_bindings": contract["evidence_bindings"],
            "passed": True,
            "checks": {check: True for check in delivery.DELIVERY_CHECKS},
            "fonts": font,
            **copy.deepcopy(observed),
        }
        with (
            patch.object(delivery, "build_presentation_contract", return_value=contract),
            patch.object(delivery, "caption_contract_sha256", return_value="d" * 64),
            patch.object(delivery, "inspect_font_license", return_value=font),
            patch.object(delivery, "inspect_delivery", return_value=observed),
        ):
            failures = delivery.validate_delivery_receipt(receipt, ROOT)
        self.assertTrue(any("presentation contract" in item for item in failures))
        self.assertTrue(any("caption contract" in item for item in failures))

    def test_incomplete_render_is_allowed_only_for_explicit_tmp_preview(self) -> None:
        contract = {
            "statuses": {"evidence_complete": False},
            "command_targets_valid": True,
            "commands": list(delivery.REPRODUCTION_COMMANDS),
        }
        with patch.object(delivery, "inspect_font_license", return_value={"passed": True}):
            with self.assertRaisesRegex(RuntimeError, "refusing final judge render"):
                delivery.require_presentation_render(
                    ROOT,
                    contract,
                    [ROOT / "artifacts/dashboard.html"],
                    allow_incomplete_preview=True,
                )
            delivery.require_presentation_render(
                ROOT,
                contract,
                [ROOT / "tmp/delivery-source-smoke/dashboard.html"],
                allow_incomplete_preview=True,
            )

    def test_dashboard_status_and_counts_are_contract_derived(self) -> None:
        module = _load_script(
            "render_champion_dashboard_test", "scripts/render_champion_dashboard.py"
        )
        contract = delivery.build_presentation_contract(ROOT)
        incomplete = copy.deepcopy(contract)
        incomplete["statuses"]["evidence_complete"] = False
        incomplete["statuses"]["agentteams"] = False
        incomplete["topology"]["official_agentteams_worker_count"] = None
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "dashboard.html"
            with (
                patch.object(module, "build_presentation_contract", return_value=incomplete),
                patch.object(module, "require_presentation_render"),
            ):
                module.render_dashboard(output)
            source = output.read_text(encoding="utf-8")
        self.assertIn("EVIDENCE BUILD IN PROGRESS", source)
        self.assertNotIn("PRE-FREEZE EVIDENCE SET COMPLETE", source)
        self.assertIn("23 protocol-simulation cases", source)
        self.assertIn("7 overflow/control-plane cases", source)
        self.assertIn(incomplete["presentation_contract_sha256"], source)

    def test_dashboard_tamper_does_not_pass_new_contract(self) -> None:
        contract = delivery.build_presentation_contract(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dashboard.html"
            path.write_text(
                "<!doctype html><html><body>RemedyFabric</body></html>" + " " * 6_000,
                encoding="utf-8",
            )
            observed = delivery.inspect_dashboard(path, contract)
        self.assertTrue(observed["structure_passed"])
        self.assertFalse(observed["text_contract_passed"])
        self.assertFalse(observed["passed"])


if __name__ == "__main__":
    unittest.main()
