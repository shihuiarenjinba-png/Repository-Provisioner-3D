"""Fail-closed CLI regression for historical Prism source-role receipt parsing."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism_artifact_role_guard import RECEIPT, SENTINEL, main


class SourceRoleReceiptCliSafetyTests(unittest.TestCase):
    def invoke(self, path):
        out = StringIO()
        with redirect_stdout(out):
            code = main([
                "--receipt", str(path),
                "--role", "sentinel_factory",
                "--artifact-id", "12909162367",
                "--source-sha", SENTINEL,
            ])
        return code, json.loads(out.getvalue())

    def test_checked_in_historical_receipt_remains_hold_only(self):
        code, result = self.invoke(RECEIPT)
        self.assertEqual(code, 0)
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["live_github_artifact_authentication"])
        self.assertFalse(result["store_submission_allowed"])

    def test_duplicate_top_level_and_nested_keys_fail_closed(self):
        valid = RECEIPT.read_text(encoding="utf-8")
        self.assertIn('"schema_version"', valid)
        for body in (
            '{"schema_version":1,"schema_version":1}',
            valid.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1),
        ):
            with self.subTest(case=body[:65]):
                with TemporaryDirectory() as tmp:
                    path = Path(tmp) / "ambiguous.json"
                    path.write_text(body, encoding="utf-8")
                    code, result = self.invoke(path)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["store_submission_allowed"])

    def test_duplicate_nested_evidence_key_fails_closed(self):
        data = RECEIPT.read_text(encoding="utf-8")
        marker = '"source_payloads": {'
        self.assertIn(marker, data)
        tampered = data.replace(marker, marker + '"original_pck_sha256": "a", ', 1)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested.json"
            path.write_text(tampered, encoding="utf-8")
            code, result = self.invoke(path)
        self.assertEqual(code, 2)
        self.assertIn("duplicate", result["reason"])
        self.assertFalse(result["store_submission_allowed"])

    def test_oversized_or_invalid_utf8_receipt_fails_closed(self):
        for payload in (b" " * 65537, b"\\xff\\xfe"):
            with self.subTest(size=len(payload)):
                with TemporaryDirectory() as tmp:
                    path = Path(tmp) / "bad.json"
                    path.write_bytes(payload)
                    code, result = self.invoke(path)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["store_submission_allowed"])


if __name__ == "__main__":
    unittest.main()
