"""Regression: real Sentinel bytes + read-only Store Identity handoff.

All positive fixtures remain HOLD; no fake UI evidence becomes CAS approval.
"""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from prism_sentinel_36_identity_handoff import verify, HandoffError
from prism_sentinel_identity_preflight import IDENTITY_MATCH, LEGACY_SOURCE

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 0, 0, tzinfo=timezone.utc)


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class TestSentinel36IdentityHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.factory = load("handoffs/prism-sentinel-factory-live-recheck-20261102.json")
        cls.provisioner = load("handoffs/prism-sentinel-qa-consumer-20261102.json")
        cls.byte_receipt = load("handoffs/prism-sentinel-live-zip-check-only-20261102-0629-jst.json")

    def inputs(self):
        return (copy.deepcopy(self.factory), copy.deepcopy(self.provisioner),
                copy.deepcopy(self.byte_receipt))

    def capture(self):
        return dict(IDENTITY_MATCH, reserved_display_name="Prism Route 3D",
                    package_identity_name="Example.TestIdentity",
                    publisher="CN=TestOnly", publisher_display_name="Test Publisher",
                    pfn="Example.TestIdentity_test", package_sid="S-1-15-2-test",
                    capture_reference="SYNTHETIC_NOT_AUTHENTICATED",
                    fixture_only=False)

    def test_real_byte_receipt_correlates_but_cas_remains_hold(self):
        result = verify(*self.inputs(), now_utc=NOW)
        self.assertTrue(result["historical_byte_receipt_correlated"])
        self.assertFalse(result["archive_bytes_rehashed_in_this_check"])
        self.assertTrue(result["historical_identity_available"])
        self.assertFalse(result["historical_identity_rebound_to_sentinel"])
        self.assertEqual(result["status"], "HOLD_OFFICIAL_IDENTITY_EVIDENCE_MISSING")
        for key in ("official_identity_cas", "package_version",
                    "signed_product_msix", "windows_all_auto_intake", "product_e2e"):
            self.assertEqual(result[key], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_complete_synthetic_ui_still_hold(self):
        result = verify(*self.inputs(), capture=self.capture(), now_utc=NOW)
        self.assertTrue(result["identity_capture_structurally_correlated"])
        self.assertFalse(result["official_partner_center_authenticated"])
        self.assertEqual(result["status"], "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED")
        self.assertEqual(result["official_identity_cas"], "HOLD")

    def test_distinct_structural_ui_reference_does_not_authenticate(self):
        capture = self.capture()
        keys = ("store_id", "reserved_display_name", "package_identity_name",
                "publisher", "publisher_display_name", "pfn", "package_sid")
        reference = {key: capture[key] for key in keys}
        reference.update(reference_origin="partner_center_ui",
                         reference_id="ANOTHER_SYNTHETIC_RECORD")
        result = verify(*self.inputs(), capture=capture,
                        comparison_reference=reference, now_utc=NOW)
        self.assertTrue(result["independent_ui_reference_structurally_compared"])
        self.assertFalse(result["official_partner_center_authenticated"])
        self.assertEqual(result["official_identity_cas"], "HOLD")
        for key in keys:
            with self.subTest(key=key), self.assertRaises(HandoffError):
                wrong = dict(reference, **{key: "MISMATCH"})
                verify(*self.inputs(), capture=capture,
                       comparison_reference=wrong, now_utc=NOW)
        with self.assertRaises(HandoffError):
            verify(*self.inputs(), capture=capture,
                   comparison_reference=dict(reference,
                                             reference_id=capture["capture_reference"]),
                   now_utc=NOW)

    def test_old_source_request_pck_manifest_and_archive_rejected(self):
        cases = (
            ("source_sha", LEGACY_SOURCE),
            ("request_id", "3d-prism-route-3d-15fdcb52e46e"),
            ("factory_build_head", LEGACY_SOURCE),
            ("factory_artifact_id", 13091630401),
            ("archive_sha256", "0" * 64),
            ("archive_size_bytes", 1),
            ("historical_store_id_reference_only", "9N0000000000"),
            ("legacy_pck_sha256", "0" * 64),
        )
        for key, wrong in cases:
            with self.subTest(key=key), self.assertRaises(HandoffError):
                f, p, b = self.inputs()
                b[key] = wrong
                verify(f, p, b, now_utc=NOW)
        with self.assertRaises(HandoffError):
            f, p, b = self.inputs()
            b["members"]["candidate.pck"]["sha256"] = "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"
            verify(f, p, b, now_utc=NOW)

    def test_unverified_bytes_and_unsafe_promotion_rejected(self):
        cases = (
            ("archive_bytes_verified_this_run", False),
            ("zip_crc_pass", False),
            ("manifest_correlated", False),
            ("historical_identity_rebound_to_sentinel", True),
            ("unsigned_qa_fixture_is_product", True),
            ("approved_package_version", "1.0.0.0"),
            ("official_identity_cas", "PASS"),
            ("signed_product_msix", "PASS"),
            ("windows_all_auto_intake", "PASS"),
            ("store_submission_allowed", True),
        )
        for key, wrong in cases:
            with self.subTest(key=key), self.assertRaises(HandoffError):
                f, p, b = self.inputs()
                b[key] = wrong
                verify(f, p, b, now_utc=NOW)

    def test_expiry_future_audit_and_invalid_time_rejected(self):
        with self.assertRaises(HandoffError):
            verify(*self.inputs(), now_utc=datetime(2026, 11, 5, 15, 24, 12,
                                                   tzinfo=timezone.utc))
        with self.assertRaises(HandoffError):
            verify(*self.inputs(), now_utc=datetime(2026, 11, 1, 20, 0,
                                                   tzinfo=timezone.utc))
        with self.assertRaises(HandoffError):
            verify(*self.inputs(), now_utc=datetime(2026, 11, 2, 0, 0))
        for invalid in ("not-a-date", "2026-11-01T21:29:16+09:00"):
            with self.subTest(invalid=invalid), self.assertRaises(HandoffError):
                f, p, b = self.inputs()
                b["verified_at_utc"] = invalid
                verify(f, p, b, now_utc=NOW)

    def test_identity_version_fixture_and_legacy_capture_rejected(self):
        for key, wrong in (
            ("source_sha", LEGACY_SOURCE),
            ("pck_sha256", "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"),
            ("store_id", "9N0000000000"),
            ("package_version", "1.0.0.0"),
            ("cas_applied", True),
            ("fixture_only", True),
            ("publisher", ""),
            ("pfn", ""),
        ):
            with self.subTest(key=key), self.assertRaises(HandoffError):
                capture = self.capture()
                capture[key] = wrong
                verify(*self.inputs(), capture=capture, now_utc=NOW)

    def test_missing_receipt_and_provisioner_drift_rejected(self):
        with self.assertRaises(HandoffError):
            f, p, _ = self.inputs()
            verify(f, p, None, now_utc=NOW)
        with self.assertRaises(HandoffError):
            f, p, b = self.inputs()
            p["official_identity_cas"] = "PASS"
            verify(f, p, b, now_utc=NOW)


if __name__ == "__main__":
    unittest.main()
