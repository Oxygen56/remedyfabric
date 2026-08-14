#!/usr/bin/env python3
"""Run the executable RemedyFabric resilience matrix and emit raw evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from remedyfabric.resilient import run_resilient_matrix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/resilient-matrix.json"),
        help="JSON evidence output path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    matrix = run_resilient_matrix()
    matrix.write(args.output)
    summary = {
        "output": str(args.output),
        "passed": matrix.passed,
        "metrics": matrix.payload["metrics"],
        "matrix_evidence_digest": matrix.payload["matrix_evidence_digest"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if matrix.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
