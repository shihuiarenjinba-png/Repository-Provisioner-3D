"""Regression: conflicting Store existence observations must block duplicate creation."""
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
        self.assertEqual(self.handoff["partner_center_product_status"], "UNRECONCILED_MANUAL_OBSERVATIONS")
        self.assertEqual(self.handoff["identity_status"], "OFFICIAL_CAPTURE_NOT_PROVEN")
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
            ("partner_center_product_status", "EXISTS_MANUAL_CONFIRMED"),
            ("partner_center_product_status", "WAITING_USER_IDENTITY"),
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

    def test_final_packaging_strategy_must_not_drift_to_gdk_or_exe_app(self):
        # Registration is derived from final MakeAppx/MSIX packaging, not
        # from the intermediate Godot EXE. Reject inconsistent handoffs.
        for key, value in (
            ("packaging_strategy", "GODOT_WINDOWS_EXE_PCK_TO_GDK_MSIXVC"),
            ("packaging_strategy", "EXE_OR_MSI_APP"),
            ("packaging_strategy", None),
            ("registration_type", "GDK_GAME"),
            ("registration_type", "EXE_OR_MSI_APP"),
            ("partner_center_selection", "GDK game"),
            ("xbox_identity_fields_required", True),
            ("xbox_identity_fields_required", None),
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

    def test_pre_and_unsigned_qa_provenance_must_remain_separate_and_consistent(self):
        validate_prism_handoff(self.handoff)
        cases = (
            ("provisioner_pre_identity_evidence", "artifact_name", "wrong-artifact"),
            ("provisioner_pre_identity_evidence", "artifact_expired_at_observation", True),
            ("provisioner_pre_identity_evidence", "run_head_sha", "f" * 40),
            ("real_makeappx_qa_evidence", "run_head_sha", "e" * 40),
            ("real_makeappx_qa_evidence", "artifact_expires_at", "not-a-date"),
            ("real_makeappx_qa_evidence", "artifact_expired_at_observation", None),
            ("real_makeappx_qa_evidence", "artifact_name",
             "prism-route-3d-provisioner-pre-identity"),
            ("factory_export_evidence", "artifact_expired_at_observation", True),
        )
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                d = copy.deepcopy(self.handoff)
                d[section][key] = value
                with self.assertRaises(HandoffContractError):
                    validate_prism_handoff(d)
        d = copy.deepcopy(self.handoff)
        d["real_makeappx_qa_evidence"]["run_id"] = d["provisioner_pre_identity_evidence"]["run_id"]
        d["real_makeappx_qa_evidence"]["artifact_id"] = d["provisioner_pre_identity_evidence"]["artifact_id"]
        with self.assertRaisesRegex(HandoffContractError, "duplicate"):
            validate_prism_handoff(d)

    def test_all_three_zip_archive_metadata_are_fail_closed(self):
        # The ZIP digest is NOT the EXE, PCK or MSIX payload digest.
        cases = (
            ("artifact_archive_digest", None),
            ("artifact_archive_digest", "a" * 64),
            ("artifact_archive_digest", "sha256:" + "g" * 64),
            ("artifact_archive_digest", "sha256:" + "a" * 63),
            ("artifact_archive_size_bytes", 0),
            ("artifact_archive_size_bytes", -1),
            ("artifact_archive_size_bytes", True),
            ("artifact_archive_size_bytes", "31022039"),
            ("artifact_expires_at", "2026-02-31T00:00:00Z"),
            ("artifact_expires_at", "2026-13-01T00:00:00Z"),
            ("artifact_expires_at", None),
        )
        for section in ("factory_export_evidence",
                        "provisioner_pre_identity_evidence",
                        "real_makeappx_qa_evidence"):
            for key, value in cases:
                with self.subTest(section=section, key=key, value=value):
                    d = copy.deepcopy(self.handoff)
                    d[section][key] = value
                    with self.assertRaises(HandoffContractError):
                        validate_prism_handoff(d)

    def test_independent_pck_diagnostic_cannot_be_swapped_or_promoted(self):
        cases = (
            ("run_id", 123),
            ("run_head_sha", "f" * 40),
            ("artifact_id", self.handoff["provisioner_pre_identity_evidence"]["artifact_id"]),
            ("artifact_name", "prism-route-3d-real-makeappx-unsigned-not-store"),
            ("artifact_archive_digest", "sha256:" + "g" * 64),
            ("artifact_archive_size_bytes", 0),
            ("artifact_expires_at", "2026-02-31T00:00:00Z"),
            ("diagnostic_only", False),
            ("not_store_payload", False),
        )
        for key, value in cases:
            with self.subTest(key=key):
                d = copy.deepcopy(self.handoff)
                d["independent_pck_diagnostic_evidence"][key] = value
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
