"""Regression: newer ORIGINAL artifacts must never be promoted as Sentinel."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from prism_artifact_role_guard import (
    ArtifactRoleError, ORIGINAL, SENTINEL, RECEIPT, select_audited_artifact,
)


class PrismArtifactSourceRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    def choose(self, role, artifact_id, source, receipt=None):
        return select_audited_artifact(
            self.receipt if receipt is None else receipt,
            role=role, artifact_id=artifact_id, expected_source_sha=source)

    def test_sentinel_factory_is_pinned_and_hold_only(self):
        r = self.choose("sentinel_factory", 12909162367, SENTINEL)
        self.assertEqual(r["status"], "HOLD_HISTORICAL_SOURCE_ROLE_DOCUMENTED")
        self.assertEqual(r["pck_sha256"],
                         self.receipt["source_payloads"]["sentinel_pck_sha256"])
        self.assertFalse(r["live_github_artifact_authentication"])
        self.assertFalse(r["store_submission_allowed"])
        self.assertEqual(r["product_e2e"], "HOLD")

    def test_original_factory_and_latest_pre_are_original_only(self):
        for role, artifact in (
            ("original_factory", 12795476435),
            ("latest_original_pre", 13019169511),
            ("latest_original_unsigned_msix", 13020309226),
        ):
            with self.subTest(role=role):
                self.assertEqual(self.choose(role, artifact, ORIGINAL)["source_sha"], ORIGINAL)
                with self.assertRaises(ArtifactRoleError):
                    self.choose(role, artifact, SENTINEL)

    def test_latest_original_msix_cannot_replace_sentinel_qa(self):
        with self.assertRaises(ArtifactRoleError):
            self.choose("latest_original_unsigned_msix", 13020309226, SENTINEL)
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_unsigned_msix", 12994295794, SENTINEL)
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_pre", 12994415760, SENTINEL)

    def test_artifact_id_mismatch_fails_even_when_exe_is_same(self):
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12795476435, SENTINEL)

    def test_pck_mismatch_evidence_fails(self):
        modified = deepcopy(self.receipt)
        modified["comparisons"]["latest_unsigned_msix_embedded_pck_matches_sentinel_factory"] = True
        with self.assertRaises(ArtifactRoleError):
            self.choose("latest_original_unsigned_msix", 13020309226, ORIGINAL, modified)

    def test_equal_pck_hashes_fail(self):
        modified = deepcopy(self.receipt)
        modified["source_payloads"]["sentinel_pck_sha256"] = modified["source_payloads"]["original_pck_sha256"]
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)

    def test_wrong_request_binding_fails(self):
        modified = deepcopy(self.receipt)
        modified["sentinel_revision"]["request_id"] = "3d-prism-route-3d-15fdcb52e46e"
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)

    def test_digest_not_verified_fails(self):
        modified = deepcopy(self.receipt)
        modified["artifacts"]["latest_original_pre"]["digest_verified_against_github_metadata"] = False
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)

    def test_unsafe_store_promotion_fails(self):
        modified = deepcopy(self.receipt)
        modified["decision"]["official_identity_cas"] = "PASS"
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)

    def test_unexpected_artifact_or_duplicate_id_fails(self):
        modified = deepcopy(self.receipt)
        modified["artifacts"]["latest_original_pre"]["artifact_id"] = 12909162367
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)


    def test_rewritten_receipt_artifact_id_is_not_an_authority(self):
        modified = deepcopy(self.receipt)
        modified["artifacts"]["sentinel_factory"]["artifact_id"] = 19999999999
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 19999999999, SENTINEL, modified)

    def test_rewritten_receipt_zip_digest_is_not_an_authority(self):
        modified = deepcopy(self.receipt)
        modified["artifacts"]["latest_original_unsigned_msix"]["downloaded_zip_sha256"] = "a" * 64
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)

    def test_rewritten_receipt_run_or_size_is_not_an_authority(self):
        for field, value in (("run_id", 49999999999), ("downloaded_zip_size_bytes", 1)):
            with self.subTest(field=field):
                modified = deepcopy(self.receipt)
                modified["artifacts"]["latest_original_pre"][field] = value
                with self.assertRaises(ArtifactRoleError):
                    self.choose("latest_original_pre", 13019169511, ORIGINAL, modified)

    def test_rewritten_distinct_pck_digest_is_not_an_authority(self):
        modified = deepcopy(self.receipt)
        modified["source_payloads"]["sentinel_pck_sha256"] = "b" * 64
        with self.assertRaises(ArtifactRoleError):
            self.choose("sentinel_factory", 12909162367, SENTINEL, modified)


if __name__ == "__main__":
    unittest.main()
