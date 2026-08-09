import json
import tempfile
import unittest
from pathlib import Path

from remedyfabric.ledger import EvidenceLedger, verify_ledger


class LedgerTests(unittest.TestCase):
    def test_valid_chain_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.jsonl"
            ledger = EvidenceLedger(path, "run")
            ledger.append("one", "a", {"value": 1})
            ledger.append("two", "b", {"value": 2})
            self.assertEqual(verify_ledger(path), (True, "ok"))
            records = path.read_text(encoding="utf-8").splitlines()
            changed = json.loads(records[0])
            changed["payload"]["value"] = 99
            records[0] = json.dumps(changed)
            path.write_text("\n".join(records) + "\n", encoding="utf-8")
            self.assertFalse(verify_ledger(path)[0])


if __name__ == "__main__":
    unittest.main()
