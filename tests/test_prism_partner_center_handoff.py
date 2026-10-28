"""Regression: an existing manually confirmed Store product cannot be recreated."""
import copy
import json
from pathlib import Path
import unittest

from partner_center_handoff_contract import (
    HandoffContractError, validate_prism_handoff,
)

HANDOFF = (Path(__file__).resolve().parents[1] / "handoffs" /
           "prism-route-3d-partner-center-product-creation.json")


class PrismHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handoff = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_current_machine_readable_handoff_is_safe(self):
        validate_prism_handoff(self.handoff)
        self.assertEqual(self.handoff["factory_export_evidence"]["run_id"], 40640951915)
        self.assertEqual(self.handoff["factory_export_evidence"]["artifact_id"], 12795476435)
        self.assertEqual(self.handoff["factory_build_head"], self.handoff["source_sha"])
        self.assertNotEqual(self.handoff["observed_factory_branch_head"],
                            self.handoff["source_sha"])

    def test_duplicate_creation_is_rejected(self):
        for value in (True, None, "true"):
            with self.subTest(value=value):
                d = copy.deepcopy(self.handoff)
                d["allow_local_product_creation"] = value
                with self.assertRaisesRegex(HandoffContractError, "duplicate"):
                    validate_prism_handoff(d)

    def test_old_not_created_and_waiting_states_are_rejected(self):
        for key, value in (
            ("partner_center_product_status", "NOT_CREATED"),
            ("identity_status", "WAITING_USER_IDENTITY"),
            ("identity_status", "IDENTITY_VALIDATED"),
            ("identity_return_cas_receipt_status", "APPLIED"),
            ("post_identity_status", "POST_IDENTITY_READY"),
        ):
            with self.subTest(key=key, value=value):
                d = copy.deepcopy(self.handoff)
                d[key] = value
                with self.assertRaises(HandoffContractError):
                    validate_prism_handoff(d)

    def test_branch_drift_must_not_mutate_pinned_source(self):
        for key, value in (
            ("source_sha", self.handoff["observed_factory_branch_head"]),
            ("factory_build_head", None),
            ("observed_factory_branch_head", self.handoff["source_sha"]),
            ("request_id", "different"),
            ("source_branch", "main"),
        ):
            with self.subTest(key=key):
                d = copy.deepcopy(self.handoff)
                d[key] = value
                with self.assertRaises(HandoffContractError):
                    validate_prism_handoff(d)

    def test_post_identity_version_and_msix_digest_are_fail_closed(self):
        for key, value in (
            ("version_status", "PASS"),
            ("approved_version", "1.0.0.0"),
            ("candidate_manifest_version", "1.0.0.0"),
            ("candidate_msix_sha256", "a" * 64),
            ("pre_identity_exe_sha256_kind", "MSIX"),
            ("identity_cas_receipt", "unverified"),
            ("version_approval_receipt", "unverified"),
            ("signature_verification_receipt", "unverified"),
            ("msix_safety_qa_receipt", "unverified"),
            ("intake_status", "READY"),
        ):
            with self.subTest(key=key):
                d = copy.deepcopy(self.handoff)
                d["post_identity_package_gate"][key] = value
                with self.assertRaises(HandoffContractError):
                    validate_prism_handoff(d)

    def test_manual_reference_does_not_authorize_store_pipeline(self):
        for key, value in (
            ("local_operator_identity_capture", "PASS"),
            ("github_to_local_trigger", "PASS"),
            ("identity_return_file_status", "EXISTS_VERIFIED"),
            ("identity_return_file_blob_sha_observed", "not-a-sha"),
        ):
            with self.subTest(key=key):
                d = copy.deepcopy(self.handoff)
                d[key] = value
                with self.assertRaises(HandoffContractError):
                    validate_prism_handoff(d)
        for key in ("second_3d_product_allowed", "store_submission_allowed",
                    "identity_guessing_allowed"):
            with self.subTest(key=key):
                d = copy.deepcopy(self.handoff)
                d["controls"][key] = True
                with self.assertRaises(HandoffContractError):
                    validate_prism_handoff(d)
        d = copy.deepcopy(self.handoff)
        d["identity_fields_required"]["store_id"] = "unverified"
        with self.assertRaises(HandoffContractError):
            validate_prism_handoff(d)


if __name__ == "__main__":
    unittest.main()
