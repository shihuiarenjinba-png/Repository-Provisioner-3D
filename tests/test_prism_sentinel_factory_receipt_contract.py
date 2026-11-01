"""Real Sentinel Factory receipt vs Provisioner handoff: fail-closed fixtures."""
import copy
import json
from pathlib import Path
import unittest

from prism_sentinel_factory_receipt_contract import check, ContractError

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "handoffs/prism-sentinel-factory-live-recheck-20261102.json"
HANDOFF = ROOT / "handoffs/prism-sentinel-qa-consumer-20261102.json"


class TestSentinelFactoryReceiptCrossContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        cls.handoff = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_exact_historical_receipt_never_grants_cas_or_store(self):
        result = check(self.receipt, self.handoff)
        self.assertTrue(result["factory_receipt_structurally_correlated"])
        self.assertFalse(result["live_archive_bytes_verified_by_this_check"])
        self.assertFalse(result["official_identity_cas_verified"])
        self.assertFalse(result["signed_product_msix_verified"])
        self.assertFalse(result["windows_all_auto_intake_verified"])
        self.assertFalse(result["store_submission_allowed"])
        self.assertEqual(result["product_e2e"], "HOLD")

    def test_source_request_build_manifest_mismatch(self):
        for field, path, value in (
            ("source", ("source", "sha"), "15fdcb52e46e35e6de8e87c55af99719c21e09b9"),
            ("request", ("source", "request_id"), "3d-prism-route-3d-15fdcb52e46e"),
            ("build", ("manifest", "factory_build_head"), "0" * 40),
            ("manifest pck", ("manifest", "pck_sha256"), "0" * 64),
            ("manifest exe", ("manifest", "exe_sha256"), "0" * 64),
            ("artifact id", ("artifact", "artifact_id"), 13068198139),
            ("archive sha", ("artifact", "archive_sha256"), "0" * 64),
            ("workflow head", ("artifact", "github_workflow_head_sha"), "0" * 40),
            ("zip member", ("members", "candidate.pck", "sha256"), "0" * 64),
            ("zip member bytes", ("members", "candidate.exe", "size_bytes"), 1),
        ):
            with self.subTest(field=field):
                r = copy.deepcopy(self.receipt)
                target = r
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ContractError):
                    check(r, self.handoff)

    def test_handoff_drift_and_legacy_pck_relabel(self):
        for path, value in (
            (("factory", "exe_sha256"), "0" * 64),
            (("factory", "pck_sha256"), "0" * 64),
            (("source_sha",), "15fdcb52e46e35e6de8e87c55af99719c21e09b9"),
            (("request_id",), "3d-prism-route-3d-15fdcb52e46e"),
            (("newer_20261101_workflow", "pck_sha256"),
             "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"),
            (("historical_identity", "verified_for_sentinel"), True),
            (("unsigned_qa_fixture", "store_product_msix"), True),
            (("official_identity_cas",), "PASS"),
            (("signed_product_msix",), "PASS"),
            (("store_submission_allowed",), True),
        ):
            with self.subTest(path=path):
                h = copy.deepcopy(self.handoff)
                target = h
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ContractError):
                    check(self.receipt, h)

    def test_archive_safety_claims_and_expiration_metadata(self):
        for path, value in (
            (("artifact", "github_metadata_expired"), True),
            (("artifact", "expires_at"), "2020-01-01T00:00:00Z"),
            (("zip", "crc_test_passed"), False),
            (("zip", "symlink_members_present"), True),
            (("zip", "exact_members"), ["candidate.exe", "candidate.exe", "export-evidence.json"]),
            (("independent_checks", "pck_sha_and_size_match_manifest"), False),
            (("downstream", "historical_identity_rebound_to_sentinel"), True),
            (("downstream", "unsigned_qa_fixture_is_store_package"), True),
            (("downstream", "package_version"), "1.0.0.0"),
        ):
            with self.subTest(path=path):
                r = copy.deepcopy(self.receipt)
                target = r
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ContractError):
                    check(r, self.handoff)


if __name__ == "__main__":
    unittest.main()
