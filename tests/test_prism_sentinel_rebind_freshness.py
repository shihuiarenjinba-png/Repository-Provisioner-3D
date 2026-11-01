"""Prism Sentinel check-only: clock freshness and genuinely distinct UI records.

Positive cases must still HOLD. These tests never authenticate Partner Center.
"""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from prism_sentinel_rebind_check_only import make_check_only, RebindError
from prism_sentinel_identity_preflight import IDENTITY_MATCH

ROOT = Path(__file__).resolve().parents[1]
EXPIRY = datetime(2026, 11, 5, 15, 24, 12, tzinfo=timezone.utc)
BEFORE = datetime(2026, 11, 2, 0, 0, 0, tzinfo=timezone.utc)


def read(name):
    return json.loads((ROOT / "handoffs" / name).read_text(encoding="utf-8"))


class TestSentinelFreshnessAndIndependentUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = read("prism-sentinel-factory-live-recheck-20261102.json")
        cls.handoff = read("prism-sentinel-qa-consumer-20261102.json")

    def inputs(self):
        receipt, handoff = copy.deepcopy(self.receipt), copy.deepcopy(self.handoff)
        a = receipt["artifact"]
        live = {
            "id": a["artifact_id"], "size_in_bytes": a["archive_size_bytes"],
            "digest": "sha256:" + a["archive_sha256"],
            "expires_at": a["expires_at"], "expired": False,
            "workflow_run": {"head_sha": receipt["source"]["sha"]},
        }
        capture = dict(IDENTITY_MATCH, reserved_display_name="Prism Route 3D",
                       package_identity_name="Example.TestIdentity",
                       publisher="CN=TestOnly", publisher_display_name="Test Publisher",
                       pfn="Example.TestIdentity_test", package_sid="S-1-15-2-test",
                       capture_reference="CAPTURE_RECORD_A", fixture_only=False)
        reference = {k: capture[k] for k in (
            "store_id", "reserved_display_name", "package_identity_name",
            "publisher", "publisher_display_name", "pfn", "package_sid")}
        reference.update(reference_origin="partner_center_ui",
                         reference_id="SEPARATE_REFERENCE_B")
        return receipt, handoff, live, capture, reference

    def test_before_deadline_still_hold_and_not_live_zip_proof(self):
        r, h, live, capture, reference = self.inputs()
        result = make_check_only(r, h, capture, live, reference, now_utc=BEFORE)
        self.assertTrue(result["factory_artifact_live_metadata_checked"])
        self.assertFalse(result["factory_archive_bytes_verified_in_this_check"])
        self.assertTrue(result["identity_comparison_records_distinct"])
        self.assertEqual(result["official_identity_cas"], "HOLD")
        self.assertEqual(result["signed_product_msix"], "HOLD")
        self.assertEqual(result["windows_all_auto_intake"], "HOLD")
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_at_or_after_deadline_fails_even_if_github_expired_false(self):
        for now in (EXPIRY, datetime(2026, 11, 6, tzinfo=timezone.utc)):
            with self.subTest(now=now), self.assertRaisesRegex(
                    RebindError, "expired by UTC deadline"):
                r, h, live, _, _ = self.inputs()
                make_check_only(r, h, live_artifact=live, now_utc=now)

    def test_timezone_conversion_and_naive_time_rejected(self):
        r, h, live, _, _ = self.inputs()
        with self.assertRaisesRegex(RebindError, "timezone-aware"):
            make_check_only(r, h, live_artifact=live,
                            now_utc=datetime(2026, 11, 2))
        from datetime import timedelta
        tokyo = timezone(timedelta(hours=9))
        result = make_check_only(r, h, live_artifact=live,
                                 now_utc=BEFORE.astimezone(tokyo))
        self.assertEqual(result["official_identity_cas"], "HOLD")

    def test_same_capture_reference_cannot_claim_independent_comparison(self):
        r, h, live, capture, reference = self.inputs()
        reference["reference_id"] = capture["capture_reference"]
        with self.assertRaisesRegex(RebindError, "reuses capture reference"):
            make_check_only(r, h, capture, live, reference, now_utc=BEFORE)

    def test_missing_or_wrong_reference_is_rejected(self):
        for key, value in (("reference_id", " "), ("reference_origin", "fixture"),
                           ("publisher", "CN=Wrong"), ("pfn", "Wrong.PFN")):
            with self.subTest(key=key), self.assertRaises(RebindError):
                r, h, live, capture, reference = self.inputs()
                reference[key] = value
                make_check_only(r, h, capture, live, reference, now_utc=BEFORE)

    def test_historical_identity_not_promoted_by_matching_reference(self):
        r, h, live, capture, reference = self.inputs()
        result = make_check_only(r, h, capture, live, reference, now_utc=BEFORE)
        self.assertTrue(result["historical_identity_available"])
        self.assertFalse(result["historical_identity_verified_for_sentinel"])
        self.assertEqual(result["status"], "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED")
        self.assertFalse(result["second_3d_product_allowed"])


if __name__ == "__main__":
    unittest.main()
