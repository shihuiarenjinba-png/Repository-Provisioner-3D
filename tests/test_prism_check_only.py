"""Fail-closed check-only regression for the single pinned real 3D Canary."""
import copy
import json
from pathlib import Path
import unittest

from partner_center_handoff_contract import HandoffContractError
from prism_check_only import prism_check_only

HANDOFF = (Path(__file__).resolve().parents[1] / "handoffs" /
           "prism-route-3d-partner-center-product-creation.json")
IDENTITY_PATH = "products/prism-route-3d/store/approved-identity.json"


class PrismCheckOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handoff = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_no_observations_is_safe_hold_not_false_pass(self):
        receipt = prism_check_only(self.handoff)
        self.assertEqual(receipt["mode"], "CHECK_ONLY_NO_SIDE_EFFECTS")
        self.assertEqual(receipt["pre_identity_status"], "PRE_IDENTITY_READY")
        self.assertEqual(receipt["product_e2e"], "HOLD")
        self.assertEqual(receipt["identity_status"],
                         "OFFICIAL_CAPTURE_AND_REQUEST_CAS_NOT_PROVEN")
        self.assertEqual(receipt["digest_roles"]["package_sha256"], None)
        self.assertIsNone(receipt["post_identity_package_gate"]["approved_four_part_version"])
        self.assertFalse(receipt["post_identity_package_gate"]["windows_all_auto_intake_allowed"])
        self.assertFalse(receipt["post_identity_package_gate"]["store_ready"])

    def test_matching_observations_do_not_authenticate_or_promote(self):
        d = self.handoff
        obs = {
            "factory_run_id": d["factory_export_evidence"]["run_id"],
            "factory_artifact_id": d["factory_export_evidence"]["artifact_id"],
            "factory_run_head": d["source_sha"],
            "factory_branch_head": d["observed_factory_branch_head"],
            "identity_file_blob_sha": d["identity_return_file_blob_sha_observed"],
            "identity_only_compare": {
                "status": "ahead", "ahead_by": 1, "behind_by": 0,
                "changed_files": [IDENTITY_PATH],
            },
            "pre_identity_exe_sha256": "a" * 64,
            "pre_identity_pck_sha256": "b" * 64,
            "unsigned_qa_msix_sha256": "c" * 64,
        }
        receipt = prism_check_only(d, obs)
        self.assertEqual(receipt["immutable_source_sha"], d["source_sha"])
        self.assertNotEqual(receipt["identity_only_descendant_head"], d["source_sha"])
        self.assertEqual(receipt["digest_roles"]["unsigned_qa_msix_sha256"], "c" * 64)
        self.assertIsNone(receipt["digest_roles"]["final_signed_msix_sha256"])
        self.assertIsNone(receipt["digest_roles"]["package_sha256"])
        self.assertEqual(receipt["product_e2e"], "HOLD")
        self.assertFalse(receipt["post_identity_package_gate"]["post_identity_ready"])
        self.assertTrue(all(v == "MATCHED_CALLER_SUPPLIED_NOT_AUTHENTICATED"
                            for v in receipt["observations"].values()))

    def test_conflicting_sha_and_run_observations_are_rejected(self):
        for key, value in (
            ("factory_run_id", 40640951916),
            ("factory_artifact_id", 12795476436),
            ("factory_run_head", "f" * 40),
            ("factory_branch_head", self.handoff["source_sha"]),
            ("identity_file_blob_sha", "f" * 40),
            ("factory_run_id", True),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(HandoffContractError, "conflicting"):
                    prism_check_only(self.handoff, {key: value})

    def test_identity_only_compare_must_be_exact_single_file_descendant(self):
        good = {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                "changed_files": [IDENTITY_PATH]}
        for key, value in (
            ("status", "diverged"), ("ahead_by", 2), ("behind_by", 1),
            ("changed_files", ["products/prism-route-3d/project.godot"]),
            ("ahead_by", True),
        ):
            with self.subTest(key=key):
                bad = dict(good)
                bad[key] = value
                with self.assertRaises(HandoffContractError):
                    prism_check_only(self.handoff, {"identity_only_compare": bad})

    def test_candidate_bytes_cannot_be_final_package_or_cas(self):
        for key, value in (
            ("final_signed_msix_sha256", "d" * 64),
            ("package_sha256", "d" * 64),
            ("approved_four_part_version", "1.0.0.0"),
            ("identity_cas_receipt", "unverified"),
            ("windows_all_auto_intake_allowed", True),
            ("store_ready", True),
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(HandoffContractError, "unexpected"):
                    prism_check_only(self.handoff, {key: value})
        for bad in (None, "A" * 64, "a" * 40, True):
            with self.subTest(digest=bad):
                with self.assertRaisesRegex(HandoffContractError, "invalid"):
                    prism_check_only(self.handoff, {"unsigned_qa_msix_sha256": bad})

    def test_corrupted_handoff_is_not_laundered_by_matching_observations(self):
        broken = copy.deepcopy(self.handoff)
        broken["post_identity_package_gate"]["intake_status"] = "READY"
        with self.assertRaises(HandoffContractError):
            prism_check_only(broken, {"factory_run_head": broken["source_sha"]})


if __name__ == "__main__":
    unittest.main()
