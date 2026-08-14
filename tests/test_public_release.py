from __future__ import annotations

import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.check_public_release import scan_paths, scan_zip


class PublicReleaseTests(unittest.TestCase):
    def test_host_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            host_path = "/" + "Users" + "/example/project"
            evidence.write_text(f'{{"workspace":"{host_path}"}}', encoding="utf-8")
            violations = scan_paths([evidence], root=root)
            self.assertEqual(violations[0]["marker"], "host_home_path")

    def test_archive_parent_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", "unsafe")
            markers = {item["marker"] for item in scan_zip(archive_path)}
            self.assertIn("unsafe_archive_path", markers)

    def test_archive_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                member = zipfile.ZipInfo("link")
                member.create_system = 3
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(member, "../outside")
            markers = {item["marker"] for item in scan_zip(archive_path)}
            self.assertIn("archive_symlink", markers)

    def test_archive_privacy_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "private.zip"
            host_path = "/" + "Users" + "/example/project"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("receipt.json", f'{{"root":"{host_path}"}}')
            markers = {item["marker"] for item in scan_zip(archive_path)}
            self.assertIn("host_home_path", markers)

    def test_clean_text_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "README.md"
            evidence.write_text("No credentials; paths are project-relative.\n", encoding="utf-8")
            self.assertEqual(scan_paths([evidence], root=root), [])

    def test_common_tokens_and_environment_assignments_are_rejected(self) -> None:
        samples = {
            "github_token": "ghp_" + "a" * 36,
            "github_pat": "github_pat_" + "a" * 30,
            "matrix_token": "syt_" + "a" * 32,
            "basic_authorization": "Authorization" + ": Basic dXNlcjpwYXNzd29yZA==",
            "secret_environment_assignment": "ACCESS" + "_KEY_SECRET=not-a-public-value",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for expected, sample in samples.items():
                with self.subTest(marker=expected):
                    path = root / f"{expected}.txt"
                    path.write_text(sample, encoding="utf-8")
                    markers = {item["marker"] for item in scan_paths([path], root=root)}
                    marker = "github_token" if expected == "github_pat" else expected
                    self.assertIn(marker, markers)


if __name__ == "__main__":
    unittest.main()
