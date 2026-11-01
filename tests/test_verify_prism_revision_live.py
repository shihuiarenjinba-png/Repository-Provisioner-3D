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
                              side_effect=error), patch.object(
                                  cli, "_authenticate_pinned_verifier",
                                  return_value={"pinned_verifier_job_authenticated": True}
                              ), redirect_stdout(stream):
                code = cli.main(["--handoff", str(path)])
            return code, json.loads(stream.getvalue())

    def test_pinned_verifier_run_job_step_authenticated(self):
        handoff = json.loads((Path(__file__).resolve().parents[1] /
            "handoffs/prism-route-3d-sentinel-revision-20261029.json"
        ).read_text(encoding="utf-8"))
        claim = handoff["pinned_snapshot_verification"]
        run = {
            "id": claim["verified_workflow_run_id"], "status": "completed",
            "conclusion": "success", "head_sha": claim["verified_workflow_head_sha"],
            "head_branch": "codex/e2e-belt-connection-20261027", "event": "push",
            "path": ".github/workflows/prism-revision-provisioner.yml",
            "workflow_id": 400477810, "repository": {"id": 1434261585},
            "head_repository": {"id": 1434261585},
        }
        job = {
            "id": claim["verified_job_id"], "run_id": claim["verified_workflow_run_id"],
            "name": "prism-revision-pre", "status": "completed",
            "conclusion": "success", "steps": [
                {"name": claim["verified_step"], "status": "completed",
                 "conclusion": "success"}
            ],
        }
        with patch.object(cli, "_github_run", return_value=run), patch.object(
                cli, "_github_json", return_value=job) as api:
            result = cli._authenticate_pinned_verifier(handoff)
        self.assertTrue(result["pinned_verifier_job_authenticated"])
        self.assertTrue(result["pinned_verifier_step_authenticated"])
        self.assertFalse(result["new_output_artifact_bytes_reverified"])
        api.assert_called_once_with(
            "/repos/shihuiarenjinba-png/Repository-Provisioner-3D/actions/jobs/"
            + str(claim["verified_job_id"]))

        from copy import deepcopy
        mutations = (
            ("wrong run HEAD", "run", "head_sha", "f" * 40),
            ("wrong workflow", "run", "workflow_id", 1),
            ("wrong run repository", "run", "repository", {"id": 1}),
            ("wrong branch", "run", "head_branch", "main"),
            ("wrong run event", "run", "event", "workflow_dispatch"),
            ("wrong job", "job", "run_id", 1),
            ("failed job", "job", "conclusion", "failure"),
            ("missing steps", "job", "steps", []),
            ("failed verifier step", "job", "steps", [
                {"name": claim["verified_step"], "status": "completed",
                 "conclusion": "failure"}]),
            ("duplicate verifier step", "job", "steps", [
                {"name": claim["verified_step"], "status": "completed",
                 "conclusion": "success"}] * 2),
        )
        for label, which, key, value in mutations:
            with self.subTest(label=label):
                bad_run, bad_job = deepcopy(run), deepcopy(job)
                (bad_run if which == "run" else bad_job)[key] = value
                with patch.object(cli, "_github_run", return_value=bad_run), patch.object(
                        cli, "_github_json", return_value=bad_job):
                    with self.assertRaises(RevisionHandoffError):
                        cli._authenticate_pinned_verifier(handoff)

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
