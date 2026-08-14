#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from remedyfabric.faultbench import run_faultbench


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentFaultBench-OSS protocol evaluation")
    parser.add_argument("--dataset", type=Path, default=Path("faultbench/cases.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/faultbench-results.json"))
    args = parser.parse_args()
    payload = run_faultbench(args.dataset, args.output)
    summary = {
        profile["profile"]: {
            key: profile[key]
            for key in (
                "safe_recovery_rate",
                "safe_containment_rate",
                "unsafe_release_rate",
                "rollback_rate",
                "single_fault_safe_recovery_rate",
                "single_fault_unsafe_release_rate",
                "overflow_containment_rate",
            )
        }
        for profile in payload["profiles"]
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
