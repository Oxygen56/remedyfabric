import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remedyfabric.cli import build_parser, command_resilient
from remedyfabric.resilient import RuntimeMatrix


class ChampionCliTests(unittest.TestCase):
    def test_resilient_command_is_public(self):
        args = build_parser().parse_args(["resilient", "--output", "receipt.json"])
        self.assertEqual(args.command, "resilient")
        self.assertEqual(args.output, "receipt.json")

    def test_resilient_command_writes_the_matrix_receipt(self):
        matrix = RuntimeMatrix(
            {
                "gate": {"passed": True},
                "metrics": {"single_worker_unsafe_releases": 0},
                "matrix_evidence_digest": "a" * 64,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt.json"
            with patch("remedyfabric.cli.run_resilient_matrix", return_value=matrix):
                returncode = command_resilient(argparse.Namespace(output=output))
            self.assertEqual(returncode, 0)
            self.assertEqual(json.loads(output.read_text())["gate"]["passed"], True)


if __name__ == "__main__":
    unittest.main()
