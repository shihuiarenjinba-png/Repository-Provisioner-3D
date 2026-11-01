"""Read-only rebind: positive structural input still HOLD; negative cases fail."""
import copy
import json
from pathlib import Path
import unittest

from prism_sentinel_rebind_check_only import make_check_only, RebindError
from prism_sentinel_identity_preflight import IDENTITY_MATCH, LEGACY_SOURCE

ROOT = Path(__file__).resolve().parents[1]

def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))

class TestSentinelRebindCheckOnly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = load("handoffs/prism-sentinel-factory-live-recheck-20261102.json")
        cls.handoff = load("handoffs/prism-sentinel-qa-consumer-20261102.json")

    def fresh(self):
        return copy.deepcopy(self.receipt), copy.deepcopy(self.handoff)

    def live(self):
        a = self.receipt["artifact"]
        return {"id": a["artifact_id"], "size_in_bytes": a["archive_size_bytes"],
                "digest": "sha256:" + a["archive_sha256"],
                "expires_at": a["expires_at"], "expired": False,
                "workflow_run": {"head_sha": self.receipt["source"]["sha"]}}

    def synthetic_capture(self):
        return dict(IDENTITY_MATCH, reserved_display_name="Prism Route 3D",
                    package_identity_name="Example.TestIdentity",
                    publisher="CN=TestOnly", publisher_display_name="Test Publisher",
                    pfn="Example.TestIdentity_test", package_sid="S-1-15-2-test",
                    capture_reference="SYNTHETIC_POSITIVE_NOT_OFFICIAL",
                    fixture_only=False)

    def test_no_capture_is_hold_and_historical_identity_retained(self):
        r, h = self.fresh()
        result = make_check_only(r, h)
        self.assertEqual(result["status"], "HOLD_OFFICIAL_IDENTITY_EVIDENCE_MISSING")
        self.assertTrue(result["historical_identity_available"])
        self.assertFalse(result["historical_identity_verified_for_sentinel"])
        self.assertFalse(result["factory_artifact_live_metadata_checked"])
        self.assertFalse(result["store_submission_allowed"])
        self.assertEqual(result["product_e2e"], "HOLD")

    def test_synthetic_complete_capture_is_not_official_cas(self):
        r, h = self.fresh()
        result = make_check_only(r, h, self.synthetic_capture(), self.live())
        self.assertEqual(result["status"], "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED")
        self.assertTrue(result["identity_capture_structurally_correlated"])
        self.assertTrue(result["factory_artifact_live_metadata_checked"])
        for key in ("official_identity_cas", "package_version",
                    "signed_product_msix", "windows_all_auto_intake", "product_e2e"):
            self.assertEqual(result[key], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_independent_ui_reference_pfn_publisher_and_identity_name(self):
        r, h = self.fresh()
        capture = self.synthetic_capture()
        keys = ("store_id", "reserved_display_name", "package_identity_name",
                "publisher", "publisher_display_name", "pfn", "package_sid")
        reference = {key: capture[key] for key in keys}
        reference.update(reference_origin="partner_center_ui",
                         reference_id="SYNTHETIC_SECOND_RECORD_NOT_AUTHENTICATED")
        result = make_check_only(r, h, capture, comparison_reference=reference)
        self.assertTrue(result["identity_fields_compared_to_reference"])
        self.assertEqual(result["official_identity_cas"], "HOLD")
        for key in keys:
            with self.subTest(key=key), self.assertRaises(RebindError):
                bad = dict(reference)
                bad[key] = "DIFFERENT"
                make_check_only(r, h, capture, comparison_reference=bad)
        with self.assertRaises(RebindError):
            make_check_only(r, h, comparison_reference=reference)
        with self.assertRaises(RebindError):
            make_check_only(r, h, capture,
                            comparison_reference=dict(reference, reference_id=""))

    def test_live_artifact_wrong_source_digest_id_expiry_fail_closed(self):
        for path, value in (
            (("id",), 13068198139),
            (("digest",), "sha256:" + "0" * 64),
            (("size_in_bytes",), 1),
            (("expired",), True),
            (("expires_at",), "2020-01-01T00:00:00Z"),
            (("workflow_run", "head_sha"), LEGACY_SOURCE),
        ):
            with self.subTest(path=path), self.assertRaises(RebindError):
                r, h = self.fresh()
                metadata = self.live()
                target = metadata
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                make_check_only(r, h, live_artifact=metadata)

    def test_real_receipt_pck_manifest_source_and_fixture_negative(self):
        for path, value in (
            (("manifest", "source_sha"), LEGACY_SOURCE),
            (("manifest", "request_id"), "3d-prism-route-3d-15fdcb52e46e"),
            (("manifest", "pck_sha256"), "0" * 64),
            (("members", "candidate.pck", "sha256"), "0" * 64),
            (("artifact", "archive_sha256"), "0" * 64),
            (("downstream", "unsigned_qa_fixture_is_store_package"), True),
            (("downstream", "package_version"), "1.0.0.0"),
        ):
            with self.subTest(path=path), self.assertRaises(RebindError):
                r, h = self.fresh()
                target = r
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                make_check_only(r, h)

    def test_historical_identity_and_unsigned_fixture_never_promoted(self):
        for path, value in (
            (("historical_identity", "verified_for_sentinel"), True),
            (("newer_20261101_workflow", "promotable_to_sentinel"), True),
            (("unsigned_qa_fixture", "store_product_msix"), True),
            (("unsigned_qa_fixture", "signature_present"), True),
            (("official_identity_cas",), "PASS"),
            (("store_submission_allowed",), True),
        ):
            with self.subTest(path=path), self.assertRaises(RebindError):
                r, h = self.fresh()
                target = h
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                make_check_only(r, h)

    def test_identity_wrong_pfn_publisher_source_version_cas_rejected(self):
        for key, value in (
            ("source_sha", LEGACY_SOURCE),
            ("pck_sha256", "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"),
            ("store_id", "9N0000000000"),
            ("publisher", ""),
            ("pfn", ""),
            ("package_version", "1.0.0.0"),
            ("cas_applied", True),
            ("fixture_only", True),
        ):
            with self.subTest(key=key), self.assertRaises(RebindError):
                r, h = self.fresh()
                capture = self.synthetic_capture()
                capture[key] = value
                make_check_only(r, h, capture)

if __name__ == "__main__":
    unittest.main()
