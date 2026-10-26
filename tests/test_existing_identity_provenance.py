"""Existing 3D Store identity must be verified without confusing blob and commit SHAs."""
import base64
import json
from pathlib import Path
import unittest

from package_identity_provisioner import (
    ConflictError, GitHubReturnClient, Job, ProductConfig,
)

CONFIG = ProductConfig.load(Path(__file__).resolve().parents[1] / "config.json")
PINNED = "a" * 40
BLOB_SHA = "b" * 40


def job():
    return Job.validate({
        "schema_version": "1.0", "request_id": "3d-test-existing-0001",
        "product_type": "GAME_3D", "source_factory": CONFIG.source_factory,
        "source_repository": CONFIG.source_repository,
        "source_branch": CONFIG.source_branch, "source_sha": PINNED,
        "slug": "sample-product", "display_name": "Sample Product",
        "target_owner": CONFIG.target_owner, "dry_run": False,
        "requested_actions": ["BUILD_WINDOWS", "INSPECT_PACKAGE",
                              "LOOKUP_OFFICIAL_IDENTITY", "PROPOSE_GITHUB_RETURN"],
    }, CONFIG)


def official():
    return {
        "store_id": "9N1234567890", "name": "Sample.Product",
        "publisher": "CN=Test Publisher", "version": "1.2.3.4",
        "authenticated_account": "operator@example.invalid",
        "official_evidence_url": "https://partner.microsoft.com/dashboard/products/123",
    }


def existing(overrides=None):
    data = {
        "reviewed": True, "source": "partner_center",
        "verified_by": official()["authenticated_account"],
        "evidence_url": official()["official_evidence_url"],
        **{k: official()[k] for k in ("store_id", "name", "publisher", "version")},
    }
    data.update(overrides or {})
    return {"sha": BLOB_SHA, "encoding": "base64",
            "content": base64.b64encode(json.dumps(data).encode()).decode()}


class FakeAPI:
    def __init__(self, prior=None, move_head=False):
        self.prior = prior if prior is not None else existing()
        self.move_head = move_head
        self.head_reads = 0
        self.writes = 0

    def __call__(self, endpoint, body=None, allow_missing=False):
        if endpoint.endswith("/git/ref/heads/" + CONFIG.source_branch):
            self.head_reads += 1
            sha = ("c" * 40 if self.move_head and self.head_reads > 1 else PINNED)
            return {"object": {"sha": sha}}
        if "/project.godot" in endpoint:
            return {"encoding": "base64",
                    "content": base64.b64encode(b"run/main_scene=x").decode()}
        if "/export_presets.cfg" in endpoint:
            return {"encoding": "base64",
                    "content": base64.b64encode(
                        b'[preset.0]\\nname="Windows Desktop"\\nplatform="Windows Desktop"\\n'
                    ).decode()}
        if "/approved-identity.json" in endpoint:
            return self.prior
        self.writes += 1
        raise AssertionError("Existing identity must never be overwritten")


class ExistingIdentityRegressionTests(unittest.TestCase):
    def test_existing_verified_returns_pinned_commit_not_blob(self):
        api = FakeAPI()
        result = GitHubReturnClient(api).return_identity(job(), CONFIG, official(), True)
        self.assertEqual(result["status"], "EXISTING_VERIFIED")
        self.assertEqual(result["commit_sha"], PINNED)
        self.assertNotEqual(result["commit_sha"], BLOB_SHA)
        self.assertEqual(api.head_reads, 2)
        self.assertEqual(api.writes, 0)

    def test_missing_review_is_conflict(self):
        api = FakeAPI(existing({"reviewed": False}))
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), True)
        self.assertEqual(api.writes, 0)

    def test_wrong_operator_is_conflict(self):
        api = FakeAPI(existing({"verified_by": "other-operator"}))
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), True)
        self.assertEqual(api.writes, 0)

    def test_wrong_evidence_url_is_conflict(self):
        api = FakeAPI(existing({"evidence_url": "https://partner.microsoft.com/other"}))
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), True)
        self.assertEqual(api.writes, 0)

    def test_head_changes_during_read_is_conflict(self):
        api = FakeAPI(move_head=True)
        with self.assertRaisesRegex(ConflictError, "HEAD changed"):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), True)
        self.assertEqual(api.head_reads, 2)
        self.assertEqual(api.writes, 0)


if __name__ == "__main__":
    unittest.main()
