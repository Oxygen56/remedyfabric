from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class EvidenceLedger:
    """Append-only, hash-chained evidence receipts for one recovery run."""

    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = GENESIS
        self.sequence = 0

    def append(self, event: str, actor: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.sequence += 1
        body = {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            "actor": actor,
            "payload": payload,
            "previous_hash": self.previous_hash,
        }
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        body["receipt_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n")
        self.previous_hash = body["receipt_hash"]
        return body


def verify_ledger(path: Path) -> tuple[bool, str]:
    previous = GENESIS
    expected_sequence = 1
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        claimed_hash = record.pop("receipt_hash")
        if record.get("sequence") != expected_sequence:
            return False, f"sequence mismatch at {expected_sequence}"
        if record.get("previous_hash") != previous:
            return False, f"chain mismatch at {expected_sequence}"
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if computed != claimed_hash:
            return False, f"hash mismatch at {expected_sequence}"
        previous = claimed_hash
        expected_sequence += 1
    return expected_sequence > 1, "ok"
