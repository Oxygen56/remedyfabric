#!/usr/bin/env python3
"""Finalize a minimized operator capture from a real official AgentTeams run.

The private input must already contain only the whitelisted runtime, Matrix,
tool, ACL, and provider fields defined by ``agentteams_evidence``.  This tool
binds the capture to the exact public source tree and refuses to publish an
invalid or credential-bearing record.  It does not manufacture missing events.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from remedyfabric.agentteams_evidence import file_digest, persist_validated_live_evidence
from remedyfabric.release_integrity import source_tree_digest

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-private", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts/agentteams-live-evidence.json",
    )
    args = parser.parse_args()
    evidence = json.loads(args.input_private.read_text(encoding="utf-8"))
    capture = evidence.setdefault("capture_bundle", {})
    capture["capture_tool_sha256"] = file_digest(Path(__file__))
    capture["source_tree_sha256"] = source_tree_digest(ROOT)
    capture["team_manifest_sha256"] = file_digest(ROOT / "agentteams/remedyfabric-live-local.yaml")
    capture["image_lock_sha256"] = file_digest(
        ROOT / "agentteams/official-runtime-images.lock.json"
    )
    written = persist_validated_live_evidence(args.output, evidence)
    if written["validation"]["passed"]:
        print(args.output)
        return 0
    print(json.dumps(written["validation"], ensure_ascii=False), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
