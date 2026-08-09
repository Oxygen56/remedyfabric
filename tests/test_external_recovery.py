import sys
import tempfile
import unittest
from pathlib import Path

from remedyfabric.models import Incident
from remedyfabric.orchestrator import RecoveryFabric


class ExternalRecoveryTests(unittest.TestCase):
    def test_arbitrary_workspace_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app").mkdir()
            (root / "tests").mkdir()
            (root / "invariants").mkdir()
            (root / "app/__init__.py").write_text("")
            (root / "app/service.py").write_text(
                "def normalize(value):\n    return value.strip().lower()\n"
            )
            test = (
                "import unittest\nfrom app.service import normalize\n"
                "class T(unittest.TestCase):\n"
                "    def test_none(self): self.assertEqual(normalize(None), '')\n"
            )
            invariant = (
                "import unittest\nfrom app.service import normalize\n"
                "class T(unittest.TestCase):\n"
                "    def test_text(self): self.assertEqual(normalize(' OK '), 'ok')\n"
            )
            (root / "tests/test_service.py").write_text(test)
            (root / "invariants/test_invariant.py").write_text(invariant)
            command = (sys.executable, "-m", "unittest", "discover", "-s", "tests")
            invariant_command = (sys.executable, "-m", "unittest", "discover", "-s", "invariants")
            incident = Incident(
                "external",
                "normal",
                root,
                command,
                invariant_command,
                "recovered",
                "external repository contract",
            )
            result = RecoveryFabric(root / "evidence").run(incident)
            self.assertTrue(result.task_success)
            self.assertIn("value is None", (root / "app/service.py").read_text())


if __name__ == "__main__":
    unittest.main()
