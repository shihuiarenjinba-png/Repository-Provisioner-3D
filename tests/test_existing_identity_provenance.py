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
        "package_family_name": "Sample.Product_testpublisher",
        "package_sid": "S-1-15-2-1-2-3-4-5-6-7",
        "authenticated_account": "operator@example.invalid",
        "official_evidence_url": "https://partner.microsoft.com/dashboard/products/123",
    }


def package():
    return {
        "kind": "exe", "sha256": "d" * 64, "signature_status": "UNSIGNED",
        "package_identity": None, "publisher": None, "version": None,
        "package_family_name": None, "package_sid": None,
    }


def existing(overrides=None):
    data = {
        "reviewed": True, "source": "partner_center",
        "request_id": job().request_id, "product_type": job().product_type,
        "source_factory": job().source_factory, "source_repository": job().source_repository,
        "source_branch": job().source_branch, "slug": job().slug,
        "verified_by": official()["authenticated_account"],
        "evidence_url": official()["official_evidence_url"],
        "verified_source_sha": PINNED, "expected_head_sha": PINNED,
        "local_package_sha256": package()["sha256"], "local_package_kind": "exe",
        "local_signature_status": "UNSIGNED",
        **{k: official()[k] for k in ("store_id", "name", "publisher", "version",
                                     "package_family_name", "package_sid")},
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
                        b'[preset.0]\nname="Windows Desktop"\nplatform="Windows Desktop"\n'
                    ).decode()}
        if "/approved-identity.json" in endpoint:
            return self.prior
        self.writes += 1
        raise AssertionError("Existing identity must never be overwritten")


class ExistingIdentityRegressionTests(unittest.TestCase):
    def test_existing_verified_returns_pinned_commit_not_blob(self):
        api = FakeAPI()
        result = GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
        self.assertEqual(result["status"], "EXISTING_VERIFIED")
        self.assertEqual(result["commit_sha"], PINNED)
        self.assertNotEqual(result["commit_sha"], BLOB_SHA)
        self.assertEqual(api.head_reads, 2)
        self.assertEqual(api.writes, 0)

    def test_missing_review_is_conflict(self):
        api = FakeAPI(existing({"reviewed": False}))
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
        self.assertEqual(api.writes, 0)

    def test_wrong_operator_is_conflict(self):
        api = FakeAPI(existing({"verified_by": "other-operator"}))
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
        self.assertEqual(api.writes, 0)

    def test_wrong_evidence_url_is_conflict(self):
        api = FakeAPI(existing({"evidence_url": "https://partner.microsoft.com/other"}))
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
        self.assertEqual(api.writes, 0)

    def test_wrong_or_missing_verified_source_sha_is_conflict(self):
        for value in ("c" * 40, None):
            with self.subTest(value=value):
                api = FakeAPI(existing({"verified_source_sha": value}))
                with self.assertRaises(ConflictError):
                    GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
                self.assertEqual(api.writes, 0)

    def test_new_identity_commit_contains_verified_source_sha(self):
        class CaptureAPI(FakeAPI):
            def __init__(self):
                super().__init__(prior=None)
                self.captured = None

            def __call__(self, endpoint, body=None, allow_missing=False):
                if "/approved-identity.json" in endpoint:
                    return None
                if endpoint == "graphql":
                    self.captured = body
                    return {"data": {"createCommitOnBranch": {"commit": {
                        "oid": "d" * 40, "url": "https://github.invalid/c"
                    }}}}
                return super().__call__(endpoint, body=body, allow_missing=allow_missing)

        api = CaptureAPI()
        result = GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
        self.assertEqual(result["status"], "APPLIED")
        addition = api.captured["variables"]["input"]["fileChanges"]["additions"][0]
        approved = json.loads(base64.b64decode(addition["contents"]))
        self.assertEqual(approved["verified_source_sha"], PINNED)
        self.assertTrue(approved["reviewed"])
        self.assertEqual(approved["source"], "partner_center")

    def test_head_changes_during_read_is_conflict(self):
        api = FakeAPI(move_head=True)
        with self.assertRaisesRegex(ConflictError, "HEAD changed"):
            GitHubReturnClient(api).return_identity(job(), CONFIG, official(), package(), True)
        self.assertEqual(api.head_reads, 2)
        self.assertEqual(api.writes, 0)


if __name__ == "__main__":
    unittest.main()
