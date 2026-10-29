"""Offline regression tests for the read-only live Prism handoff CLI."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

import verify_prism_revision_live as cli
from prism_revision_handoff_contract import RevisionHandoffError


class LivePrismHandoffCliTests(unittest.TestCase):
    def test_github_api_is_read_only(self):
        with patch.object(cli.subprocess, "run", return_value=Mock(stdout='{"id": 7}')) as run:
            self.assertEqual(cli._github_run("owner/repo", 7)["id"], 7)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["gh", "api", "--method", "GET",
                                   "/repos/owner/repo/actions/runs/7"])
        self.assertTrue(kwargs["check"])
        self.assertGreater(kwargs["timeout"], 0)

    def test_artifact_list_must_be_complete(self):
        with patch.object(cli, "_github_json", return_value={
            "total_count": 101, "artifacts": [{"id": 1}]
        }):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                cli._github_artifacts("owner/repo", 7)
        with patch.object(cli, "_github_json", return_value={
            "total_count": True, "artifacts": [{"id": 1}]
        }):
            with self.assertRaises(ValueError):
                cli._github_artifacts("owner/repo", 7)

    def test_bad_api_shape_rejected(self):
        with patch.object(cli.subprocess, "run", return_value=Mock(stdout="[]")):
            with self.assertRaisesRegex(ValueError, "not an object"):
                cli._github_run("owner/repo", 7)

    def run_cli(self, receipt=None, error=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "handoff.json"
            path.write_text("{}", encoding="utf-8")
            stream = io.StringIO()
            with patch.object(cli, "verify_github_metadata", return_value=receipt,
                              side_effect=error), redirect_stdout(stream):
                code = cli.main(["--handoff", str(path)])
            return code, json.loads(stream.getvalue())

    def test_verified_metadata_remains_hold(self):
        receipt = {"status": "GITHUB_METADATA_MATCH_HOLD_PAYLOAD_NOT_VERIFIED",
                   "product_e2e": "HOLD", "store_submission_allowed": False}
        code, result = self.run_cli(receipt=receipt)
        self.assertEqual(code, 0)
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_unexpected_store_authorization_rejected(self):
        receipt = {"status": "GITHUB_METADATA_MATCH_HOLD_PAYLOAD_NOT_VERIFIED",
                   "product_e2e": "PASS", "store_submission_allowed": True}
        code, result = self.run_cli(receipt=receipt)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_remote_or_identity_failure_fails_closed(self):
        code, result = self.run_cli(error=RevisionHandoffError("unverified"))
        self.assertEqual(code, 2)
        self.assertEqual(result["github_metadata_verified"], False)
        self.assertFalse(result["store_submission_allowed"])


if __name__ == "__main__":
    unittest.main()
