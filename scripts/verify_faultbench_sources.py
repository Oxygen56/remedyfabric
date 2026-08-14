#!/usr/bin/env python3
"""Verify every FaultBench provenance record against GitHub's official REST API."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from remedyfabric.faultbench import OSSCase, load_cases


def _gh_api(endpoint: str) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            endpoint,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown gh api error"
        raise RuntimeError(f"GitHub API request failed for {endpoint}: {detail}")
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise TypeError(f"GitHub API returned a non-object for {endpoint}")
    return payload


def _assert_equal(
    checks: list[dict[str, Any]],
    *,
    name: str,
    expected: Any,
    observed: Any,
) -> None:
    checks.append(
        {
            "field": name,
            "expected": expected,
            "observed": observed,
            "passed": expected == observed,
        }
    )


def validate_api_payloads(
    case: OSSCase,
    pull: dict[str, Any],
    commit: dict[str, Any],
    license_payload: dict[str, Any],
    issue: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare one case with raw official API payloads without making network calls."""

    checks: list[dict[str, Any]] = []
    _assert_equal(checks, name="pull.html_url", expected=case.pr_url, observed=pull.get("html_url"))
    _assert_equal(checks, name="pull.number", expected=case.pr_number, observed=pull.get("number"))
    _assert_equal(checks, name="pull.state", expected="closed", observed=pull.get("state"))
    _assert_equal(checks, name="pull.merged", expected=True, observed=pull.get("merged"))
    _assert_equal(checks, name="pull.title", expected=case.title, observed=pull.get("title"))
    _assert_equal(
        checks, name="pull.merged_at", expected=case.merged_at, observed=pull.get("merged_at")
    )
    _assert_equal(
        checks,
        name="pull.merge_commit_sha",
        expected=case.fixed_commit_sha,
        observed=pull.get("merge_commit_sha"),
    )
    _assert_equal(
        checks,
        name="commit.sha",
        expected=case.fixed_commit_sha,
        observed=commit.get("sha"),
    )
    _assert_equal(
        checks,
        name="commit.html_url",
        expected=case.commit_url,
        observed=commit.get("html_url"),
    )
    _assert_equal(
        checks,
        name="repository.license.spdx_id",
        expected=case.license,
        observed=(license_payload.get("license") or {}).get("spdx_id"),
    )
    if case.issue_url is not None:
        _assert_equal(
            checks,
            name="issue.html_url",
            expected=case.issue_url,
            observed=(issue or {}).get("html_url"),
        )
    return {
        "case_id": case.case_id,
        "repository": case.repository,
        "pr_api_endpoint": f"repos/{case.repository}/pulls/{case.pr_number}",
        "commit_api_endpoint": f"repos/{case.repository}/commits/{case.fixed_commit_sha}",
        "license_api_endpoint": f"repos/{case.repository}/license",
        "issue_api_endpoint": (
            "repos/" + case.repository + "/issues/" + case.issue_url.rsplit("/", maxsplit=1)[-1]
            if case.issue_url
            else None
        ),
        "checks": checks,
        "passed": all(check["passed"] for check in checks),
    }


def verify_sources(dataset: Path, output: Path, raw_output: Path) -> dict[str, Any]:
    cases = load_cases(dataset)
    licenses: dict[str, dict[str, Any]] = {}
    raw_cases: dict[str, dict[str, Any]] = {}
    validations: list[dict[str, Any]] = []
    for case in cases:
        license_payload = licenses.get(case.repository)
        if license_payload is None:
            license_payload = _gh_api(f"repos/{case.repository}/license")
            licenses[case.repository] = license_payload
        pull = _gh_api(f"repos/{case.repository}/pulls/{case.pr_number}")
        commit = _gh_api(f"repos/{case.repository}/commits/{case.fixed_commit_sha}")
        issue = None
        if case.issue_url is not None:
            issue_number = case.issue_url.rsplit("/", maxsplit=1)[-1]
            issue = _gh_api(f"repos/{case.repository}/issues/{issue_number}")
        validations.append(validate_api_payloads(case, pull, commit, license_payload, issue))
        raw_cases[case.case_id] = {
            "pull_request": pull,
            "commit": commit,
            "issue": issue,
        }

    rate_limit = _gh_api("rate_limit")
    raw_receipt = {
        "receipt_schema_version": "1.0",
        "provider": "GitHub official REST API",
        "api_version": "2022-11-28",
        "retrieved_at": datetime.now(UTC).isoformat(),
        "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
        "licenses": licenses,
        "cases": raw_cases,
        "rate_limit_after_requests": rate_limit,
        "redaction": "No credentials or request headers are stored; response JSON is public data.",
    }
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    raw_bytes = (json.dumps(raw_receipt, ensure_ascii=False, indent=2) + "\n").encode()
    raw_output.write_bytes(raw_bytes)

    failed = [validation["case_id"] for validation in validations if not validation["passed"]]
    summary = {
        "schema_version": "1.0",
        "status": "verified" if not failed else "mismatch",
        "provider": "GitHub official REST API",
        "api_version": "2022-11-28",
        "verified_at": raw_receipt["retrieved_at"],
        "dataset": str(dataset),
        "dataset_sha256": raw_receipt["dataset_sha256"],
        "raw_receipt_publication": (
            "local-only; the public summary retains its SHA-256 and all compared fields"
        ),
        "raw_receipt_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "case_count": len(cases),
        "repository_count": len(licenses),
        "failed_case_ids": failed,
        "validations": validations,
        "claims_boundary": (
            "This receipt verifies public GitHub PR, merge commit, issue-link, and repository "
            "license metadata at retrieval time. It does not verify defect reproducibility, "
            "patch correctness, contributor intent, or dependency/build availability."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("faultbench/cases.json"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/faultbench-source-verification.json"),
    )
    parser.add_argument(
        "--raw-output",
        type=Path,
        default=Path("artifacts/faultbench-source-verification.raw.json"),
    )
    args = parser.parse_args()
    try:
        result = verify_sources(args.dataset, args.output, args.raw_output)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(
            json.dumps({"status": "error", "error": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "status": result["status"],
                "case_count": result["case_count"],
                "repository_count": result["repository_count"],
                "failed_case_ids": result["failed_case_ids"],
                "raw_receipt_sha256": result["raw_receipt_sha256"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
