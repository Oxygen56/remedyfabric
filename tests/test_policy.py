import tempfile
import unittest
from pathlib import Path

from remedyfabric.models import FileEdit, PatchCandidate
from remedyfabric.policy import RecoveryPolicy


class PolicyTests(unittest.TestCase):
    def evaluate(self, path: str, new: str = "fixed"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            return RecoveryPolicy().evaluate(
                root,
                PatchCandidate("test", "diagnosis", (FileEdit(path, "old", new, "reason"),), 1.0),
            )

    def test_allows_small_source_edit(self):
        self.assertTrue(self.evaluate("app/service.py").approved)

    def test_rejects_tests(self):
        self.assertFalse(self.evaluate("tests/test_service.py").approved)

    def test_rejects_workflow(self):
        self.assertFalse(self.evaluate(".github/workflows/release.yml").approved)

    def test_rejects_path_escape(self):
        self.assertFalse(self.evaluate("../outside.txt").approved)

    def test_rejects_possible_secret(self):
        self.assertFalse(self.evaluate("app/config.py", 'API_KEY="not-a-real-secret"').approved)


if __name__ == "__main__":
    unittest.main()
