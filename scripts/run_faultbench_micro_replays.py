#!/usr/bin/env python3
"""Execute the three language-specific AgentFaultBench semantic micro-replays."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "faultbench" / "micro_replays"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def _parse_result(completed: subprocess.CompletedProcess[str], case_id: str) -> dict[str, Any]:
    if completed.returncode != 0:
        return {
            "passed": False,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "error": "fixture process returned non-zero",
        }
    try:
        observed = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return {
            "passed": False,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "error": f"fixture did not emit JSON: {error}",
        }
    passed = (
        observed.get("case_id") == case_id
        and observed.get("before_defect_observed") is True
        and observed.get("after_expectation_passed") is True
    )
    return {
        "passed": passed,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "observed": observed,
    }


def run_micro_replays(output: Path) -> dict[str, Any]:
    python_source = FIXTURE_ROOT / "python_requests_7308" / "replay.py"
    javascript_source = FIXTURE_ROOT / "javascript_fastify_6838" / "replay.js"
    rust_source = FIXTURE_ROOT / "rust_axum_3848" / "replay.rs"
    node = shutil.which("node")
    rustc = shutil.which("rustc")

    fixture_specs: list[tuple[str, str, Path, Path]] = [
        (
            "requests-7308",
            "Python",
            python_source,
            python_source.parent / "provenance.json",
        ),
        (
            "fastify-6838",
            "JavaScript",
            javascript_source,
            javascript_source.parent / "provenance.json",
        ),
        ("axum-3848", "Rust", rust_source, rust_source.parent / "provenance.json"),
    ]
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="remedyfabric-micro-replay-") as temporary:
        binary = Path(temporary) / "axum-3848-replay"
        rust_compile = (
            _run([rustc, "--edition=2021", str(rust_source), "-o", str(binary)], timeout=60)
            if rustc
            else None
        )
        commands: dict[str, subprocess.CompletedProcess[str] | None] = {
            "requests-7308": _run([sys.executable, str(python_source)]),
            "fastify-6838": _run([node, str(javascript_source)]) if node else None,
            "axum-3848": (
                _run([str(binary)]) if rust_compile and rust_compile.returncode == 0 else None
            ),
        }
        for case_id, language, source, provenance_path in fixture_specs:
            completed = commands[case_id]
            if completed is None:
                parsed: dict[str, Any] = {
                    "passed": False,
                    "error": (
                        "required runtime unavailable or Rust compilation failed: "
                        + (
                            (rust_compile.stderr if rust_compile else "")
                            if language == "Rust"
                            else ""
                        )
                    ),
                }
            else:
                parsed = _parse_result(completed, case_id)
            parsed.update(
                {
                    "case_id": case_id,
                    "language": language,
                    "source": str(source.relative_to(ROOT)),
                    "source_sha256": _sha256(source),
                    "provenance": json.loads(provenance_path.read_text(encoding="utf-8")),
                }
            )
            results.append(parsed)

    tool_versions: dict[str, str | None] = {"python": sys.version.split()[0]}
    for name, executable in (("node", node), ("rustc", rustc)):
        if executable:
            version = _run([executable, "--version"])
            tool_versions[name] = version.stdout.strip() if version.returncode == 0 else None
        else:
            tool_versions[name] = None
    payload = {
        "schema_version": "1.0",
        "status": "passed" if all(result["passed"] for result in results) else "failed",
        "fixture_count": len(results),
        "language_count": len({result["language"] for result in results}),
        "tool_versions": tool_versions,
        "results": results,
        "claims_boundary": (
            "Each result is a real execution of an independently written semantic micro-replay "
            "derived from a linked public diff. No upstream repository was cloned, no upstream "
            "dependency was installed, and no complete upstream test suite or repair was run."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/faultbench-micro-replays.json"),
    )
    args = parser.parse_args()
    result = run_micro_replays(args.output)
    print(
        json.dumps(
            {
                "status": result["status"],
                "fixture_count": result["fixture_count"],
                "language_count": result["language_count"],
            },
            indent=2,
        )
    )
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
