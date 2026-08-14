from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from remedyfabric.public_ci_validation import (
    CLEAN_ARTIFACT_ZIP_PATH,
    RECEIPT_JOB_ALIASES,
    REQUIRED_JOBS,
    capture_public_ci_receipt,
    expected_clean_artifact_members,
    inspect_clean_release_artifact_zip,
    validate_public_ci_receipt,
)


class PublicCIValidationTests(unittest.TestCase):
    head = "a" * 40
    run_id = 456
    artifact_id = 789
    run_url = "https://github.com/Oxygen56/remedyfabric/actions/runs/456"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.artifact_zip = Path(self.temporary.name) / "clean-release-ci.zip"
        self.member_bytes = {
            "artifacts/clean-replay.json": b'{"passed":true}\n',
            "dist/remedyfabric-0.2.0-py3-none-any.whl": b"wheel-bytes",
            "dist/remedyfabric-0.2.0.tar.gz": b"sdist-bytes",
        }
        self._write_artifact_zip(self.member_bytes)

    def _write_artifact_zip(self, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(self.artifact_zip, "w") as archive:
            for name, content in members.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, content)

    def run_payload(self) -> dict[str, object]:
        return {
            "id": self.run_id,
            "repository": {"full_name": "Oxygen56/remedyfabric"},
            "head_sha": self.head,
            "status": "completed",
            "conclusion": "success",
            "path": ".github/workflows/ci.yml",
            "html_url": self.run_url,
            "run_attempt": 1,
            "updated_at": "2026-08-13T08:00:00Z",
        }

    @staticmethod
    def jobs_payload() -> dict[str, object]:
        return {
            "total_count": 5,
            "jobs": [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in REQUIRED_JOBS
            ],
        }

    def artifact_record(self) -> dict[str, object]:
        zip_digest = hashlib.sha256(self.artifact_zip.read_bytes()).hexdigest()
        return {
            "id": self.artifact_id,
            "name": f"clean-release-{self.head}",
            # Service metadata is intentionally distinct from downloaded ZIP bytes.
            "size_in_bytes": self.artifact_zip.stat().st_size + 137,
            "digest": f"sha256:{zip_digest}",
            "expired": False,
            "url": ("https://api.github.com/repos/Oxygen56/remedyfabric/actions/artifacts/789"),
            "archive_download_url": (
                "https://api.github.com/repos/Oxygen56/remedyfabric/actions/artifacts/789/zip"
            ),
            "created_at": "2026-08-13T08:00:00Z",
            "updated_at": "2026-08-13T08:01:00Z",
            "expires_at": "2026-08-20T08:00:00Z",
            "workflow_run": {"id": self.run_id, "head_sha": self.head},
        }

    def artifacts_payload(self) -> dict[str, object]:
        return {"total_count": 1, "artifacts": [self.artifact_record()]}

    def receipt(self) -> dict[str, object]:
        run = self.run_payload()
        jobs = self.jobs_payload()
        artifacts = self.artifacts_payload()
        zip_receipt = inspect_clean_release_artifact_zip(self.artifact_zip)
        return {
            "schema_version": "1.1",
            "repository": "Oxygen56/remedyfabric",
            "workflow_path": ".github/workflows/ci.yml",
            "run_id": self.run_id,
            "run_attempt": 1,
            "head_sha": self.head,
            "status": "completed",
            "conclusion": "success",
            "html_url": self.run_url,
            "jobs": {alias: "success" for alias in RECEIPT_JOB_ALIASES},
            "live_run_payload_sha256": hashlib.sha256(
                json.dumps(run, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "live_jobs_payload_sha256": hashlib.sha256(
                json.dumps(jobs, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "live_artifacts_payload_sha256": hashlib.sha256(
                json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "clean_release_artifact": {
                "metadata": self.artifact_record(),
                "zip": zip_receipt,
            },
        }

    def test_capture_binds_completed_run_jobs_metadata_and_raw_zip(self) -> None:
        with patch(
            "remedyfabric.public_ci_validation._live_payloads",
            return_value=(
                self.run_payload(),
                self.jobs_payload(),
                self.artifacts_payload(),
            ),
        ):
            receipt = capture_public_ci_receipt(
                self.run_url,
                self.head,
                self.artifact_zip,
            )
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(set(receipt["jobs"]), RECEIPT_JOB_ALIASES)
        artifact = receipt["clean_release_artifact"]
        self.assertEqual(artifact["metadata"]["id"], self.artifact_id)
        self.assertEqual(
            artifact["metadata"]["digest"],
            f"sha256:{artifact['zip']['sha256']}",
        )
        self.assertNotEqual(artifact["metadata"]["size_in_bytes"], artifact["zip"]["size_bytes"])
        self.assertEqual(set(artifact["zip"]["members"]), set(self.member_bytes))
        self.assertEqual(artifact["zip"]["path"], CLEAN_ARTIFACT_ZIP_PATH)

    def test_zip_inspection_requires_exact_three_safe_regular_members(self) -> None:
        receipt = inspect_clean_release_artifact_zip(self.artifact_zip, version="0.2.0")
        self.assertEqual(set(receipt["members"]), set(expected_clean_artifact_members("0.2.0")))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.artifact_zip, "a") as archive:
                archive.writestr("../outside", b"unsafe")
        with self.assertRaisesRegex(ValueError, "unsafe path|exactly three"):
            inspect_clean_release_artifact_zip(self.artifact_zip)

    def test_zip_inspection_rejects_symlink_member(self) -> None:
        members = dict(self.member_bytes)
        self._write_artifact_zip({})
        with zipfile.ZipFile(self.artifact_zip, "w") as archive:
            for name, content in members.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (
                    (stat.S_IFLNK if name.endswith(".whl") else stat.S_IFREG) | 0o644
                ) << 16
                archive.writestr(info, content)
        with self.assertRaisesRegex(ValueError, "exactly three regular files"):
            inspect_clean_release_artifact_zip(self.artifact_zip)

    def test_live_validation_rejects_failed_or_missing_job(self) -> None:
        jobs = self.jobs_payload()
        jobs["jobs"] = list(jobs["jobs"])[:-1]  # type: ignore[arg-type]
        with patch(
            "remedyfabric.public_ci_validation._live_payloads",
            return_value=(self.run_payload(), jobs, self.artifacts_payload()),
        ):
            failures = validate_public_ci_receipt(self.receipt(), self.head, live=True)
        self.assertTrue(any("exactly the five" in failure for failure in failures))
        self.assertTrue(any("final-evidence" in failure for failure in failures))

    def test_live_validation_rejects_running_self_receipt(self) -> None:
        run = self.run_payload()
        run["status"] = "in_progress"
        run["conclusion"] = None
        with patch(
            "remedyfabric.public_ci_validation._live_payloads",
            return_value=(run, self.jobs_payload(), self.artifacts_payload()),
        ):
            failures = validate_public_ci_receipt(self.receipt(), self.head, live=True)
        self.assertIn(
            "public CI live run metadata does not match the frozen source",
            failures,
        )

    def test_live_validation_rejects_changed_api_payload(self) -> None:
        run = self.run_payload()
        run["updated_at"] = "2026-08-13T09:00:00Z"
        with patch(
            "remedyfabric.public_ci_validation._live_payloads",
            return_value=(run, self.jobs_payload(), self.artifacts_payload()),
        ):
            failures = validate_public_ci_receipt(self.receipt(), self.head, live=True)
        self.assertIn("public CI live run payload digest changed", failures)

    def test_live_validation_rejects_expired_or_wrong_run_artifact(self) -> None:
        artifacts = self.artifacts_payload()
        artifact = artifacts["artifacts"][0]  # type: ignore[index]
        artifact["expired"] = True
        artifact["workflow_run"] = {"id": 999, "head_sha": self.head}
        with patch(
            "remedyfabric.public_ci_validation._live_payloads",
            return_value=(self.run_payload(), self.jobs_payload(), artifacts),
        ):
            failures = validate_public_ci_receipt(self.receipt(), self.head, live=True)
        self.assertTrue(any("artifact metadata is invalid" in failure for failure in failures))

    def test_capture_rejects_download_whose_digest_differs_from_github(self) -> None:
        artifacts = self.artifacts_payload()
        artifacts["artifacts"][0]["digest"] = "sha256:" + "b" * 64  # type: ignore[index]
        with (
            patch(
                "remedyfabric.public_ci_validation._live_payloads",
                return_value=(self.run_payload(), self.jobs_payload(), artifacts),
            ),
            self.assertRaisesRegex(RuntimeError, "does not match GitHub artifact metadata"),
        ):
            capture_public_ci_receipt(self.run_url, self.head, self.artifact_zip)

    def test_receipt_shape_rejects_extra_claimed_job_without_network(self) -> None:
        receipt = self.receipt()
        receipt["jobs"] = dict(receipt["jobs"]) | {"invented-job": "success"}  # type: ignore[arg-type]
        with patch("remedyfabric.public_ci_validation._live_payloads") as live:
            failures = validate_public_ci_receipt(receipt, self.head, live=True)
        self.assertTrue(any("exactly five" in failure for failure in failures))
        live.assert_not_called()

    def test_capture_rejects_wrong_head_even_when_jobs_succeed(self) -> None:
        run = self.run_payload()
        run["head_sha"] = "b" * 40
        with (
            patch(
                "remedyfabric.public_ci_validation._live_payloads",
                return_value=(run, self.jobs_payload(), self.artifacts_payload()),
            ),
            self.assertRaisesRegex(RuntimeError, "frozen source"),
        ):
            capture_public_ci_receipt(self.run_url, self.head, self.artifact_zip)


if __name__ == "__main__":
    unittest.main()
