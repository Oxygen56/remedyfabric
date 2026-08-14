#!/usr/bin/env python3
"""Fail closed when a public release contains host paths or credential-shaped values."""

from __future__ import annotations

import argparse
import json
import re
import stat
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

PATTERNS = {
    "host_home_path": re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "openai_style_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "alibaba_access_key": re.compile(r"\bLTAI[A-Za-z0-9]{12,}\b"),
    "github_token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "matrix_token": re.compile(r"\bsyt_[A-Za-z0-9._=-]{16,}\b"),
    "basic_authorization": re.compile(r"\bAuthorization\s*[:=]\s*Basic\s+\S+", re.IGNORECASE),
    "jwt_bearer": re.compile(r"\bBearer\s+eyJ[A-Za-z0-9._-]+", re.IGNORECASE),
    "secret_environment_assignment": re.compile(
        r"\b(?:TOKEN|API[_-]?KEY|ACCESS[_-]?TOKEN|ACCESS[_-]?KEY(?:[_-]?SECRET)?|"
        r"PASSWORD|SECRET)\s*=\s*(?!\[REDACTED\]|none\b|null\b|false\b|true\b|0\b)"
        r"[^\s,;\]\}\"']{8,}",
        re.IGNORECASE,
    ),
    "unresolved_placeholder": re.compile(
        r"<(?:FINAL|TODO|TBD|PLACEHOLDER|INSERT|CHANGEME)[A-Z0-9_-]*>",
        re.IGNORECASE,
    ),
    "unredacted_secret_field": re.compile(
        r'["\'](?:api[_-]?key|access[_-]?token|password|secret)["\']\s*:\s*'
        r'["\'](?!\[REDACTED\]|none|null|false|true|0|\s*["\'])[^"\']{8,}["\']',
        re.IGNORECASE,
    ),
}


def _scan_text(name: str, text: str) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for marker, pattern in PATTERNS.items():
        match = pattern.search(text)
        if match:
            violations.append(
                {
                    "file": name,
                    "marker": marker,
                    "line": text.count("\n", 0, match.start()) + 1,
                }
            )
    return violations


def scan_paths(paths: Iterable[Path], *, root: Path = ROOT) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for path in paths:
        path = path if path.is_absolute() else root / path
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append({"file": relative, "marker": "invalid_utf8", "line": None})
            continue
        violations.extend(_scan_text(relative, text))
    return violations


def scan_zip(path: Path) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        bad_member = archive.testzip()
        if bad_member:
            violations.append({"file": bad_member, "marker": "zip_crc_failure", "line": None})
        for member in archive.infolist():
            name = PurePosixPath(member.filename)
            if name.is_absolute() or ".." in name.parts:
                violations.append(
                    {"file": member.filename, "marker": "unsafe_archive_path", "line": None}
                )
            if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                violations.append(
                    {"file": member.filename, "marker": "archive_symlink", "line": None}
                )
            if name.suffix.lower() in TEXT_SUFFIXES and not member.is_dir():
                try:
                    text = archive.read(member).decode("utf-8")
                except UnicodeDecodeError:
                    violations.append(
                        {"file": member.filename, "marker": "invalid_utf8", "line": None}
                    )
                    continue
                violations.extend(_scan_text(member.filename, text))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", type=Path)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    if bool(args.zip) == bool(args.paths):
        parser.error("provide either --zip or one or more paths")
    violations = scan_zip(args.zip) if args.zip else scan_paths(args.paths)
    result = {"passed": not violations, "violations": violations}
    print(json.dumps(result, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
