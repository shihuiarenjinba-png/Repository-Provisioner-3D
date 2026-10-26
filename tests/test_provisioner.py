import unittest
from provisioner import propose
SHA="a"*40
class NamingTests(unittest.TestCase):
    def test_deterministic(self):
        row={"kind":"app","slug":"my-desktop-tool","source_sha":SHA,"status":"WINDOWS_QA_REQUIRED"}
        self.assertEqual(propose(row,"app"),propose(row,"app"))
    def test_only_names_never_creates(self):
        row={"kind":"game","slug":"my-simple-game","source_sha":SHA,"status":"WINDOWS_QA_REQUIRED"}
        item=propose(row,"game")
        self.assertFalse(item["create_allowed"])
        self.assertFalse(item["store_submission_allowed"])
    def test_kind_mismatch(self):
        row={"kind":"app","slug":"my-desktop-tool","source_sha":SHA,"status":"WINDOWS_QA_REQUIRED"}
        with self.assertRaises(ValueError):propose(row,"game")
    def test_missing_sha(self):
        row={"kind":"app","slug":"my-desktop-tool","source_sha":"","status":"WINDOWS_QA_REQUIRED"}
        with self.assertRaises(ValueError):propose(row,"app")
    def test_status_not_certified(self):
        row={"kind":"app","slug":"my-desktop-tool","source_sha":SHA,"status":"CERTIFIED"}
        with self.assertRaises(ValueError):propose(row,"app")
if __name__=="__main__":unittest.main()
