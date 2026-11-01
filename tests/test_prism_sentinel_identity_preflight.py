"""Positive/negative pre-CAS fixtures: structural PASS never means Store PASS."""
import copy
import unittest
from prism_sentinel_identity_preflight import (
    check, PreflightError, EXPECTED, IDENTITY_MATCH, LEGACY_SOURCE,
    LEGACY_COMMIT, PCK,
)

def factory():
    return dict(EXPECTED, fixture_identity=False,
                signature_present=False, product_msix=False)

def capture():
    return dict(IDENTITY_MATCH, reserved_display_name="Prism Route 3D",
                package_identity_name="Example.TestIdentity",
                publisher="CN=TestOnly", publisher_display_name="Test Publisher",
                pfn="Example.TestIdentity_test", package_sid="S-1-15-2-test",
                capture_reference="SYNTHETIC_POSITIVE_TEST_NOT_OFFICIAL",
                fixture_only=False)

class TestSentinelPreCAS(unittest.TestCase):
    def test_no_capture_is_hold(self):
        r = check(factory())
        self.assertEqual(r["status"], "HOLD_OFFICIAL_IDENTITY_EVIDENCE_MISSING")
        self.assertFalse(r["store_submission_allowed"])

    def test_complete_synthetic_positive_still_hold(self):
        r = check(factory(), capture())
        self.assertTrue(r["identity_fields_structurally_correlated"])
        self.assertEqual(r["status"], "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED")
        self.assertFalse(r["official_identity_cas_verified"])
        self.assertFalse(r["approved_version_verified"])
        self.assertFalse(r["signed_product_msix_verified"])

    def test_independent_factory_anchors(self):
        for key, wrong in (
            ("source_sha", LEGACY_SOURCE), ("request_id", "old-request"),
            ("factory_build_head", LEGACY_SOURCE),
            ("factory_artifact_id", 13068198139),
            ("factory_archive_sha256", "0" * 64),
            ("exe_sha256", "0" * 64), ("pck_sha256", "0" * 64),
            ("registration_type", "GDK_GAME"),
            ("artifact_role", "UNSIGNED_QA_FIXTURE"),
            ("packaging_strategy", "GDK_MSIXVC"),
        ):
            with self.subTest(key=key), self.assertRaises(PreflightError):
                data = factory()
                data[key] = wrong
                check(data)

    def test_legacy_identity_never_auto_reused(self):
        for key, wrong in (
            ("source_sha", LEGACY_SOURCE),
            ("request_id", "3d-prism-route-3d-15fdcb52e46e"),
            ("factory_build_head", LEGACY_SOURCE),
            ("pck_sha256", "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"),
            ("factory_artifact_id", 13068198139),
            ("store_id", "9N0000000000"),
            ("partner_center_selection", "GDK game"),
            ("historical_identity_commit", LEGACY_COMMIT),
        ):
            with self.subTest(key=key), self.assertRaises(PreflightError):
                item = capture()
                item[key] = wrong
                check(factory(), item)

    def test_missing_required_official_fields(self):
        for key in ("reserved_display_name", "package_identity_name",
                    "publisher", "publisher_display_name", "pfn",
                    "package_sid", "capture_reference"):
            with self.subTest(key=key), self.assertRaises(PreflightError):
                item = capture()
                item.pop(key)
                check(factory(), item)

    def test_version_and_authorization_injection(self):
        for key, value in (("version", "1.0.0.0"),
                           ("package_version", "1.0.0.0"),
                           ("cas_applied", True),
                           ("store_submission_allowed", True),
                           ("signed_product_msix", True)):
            with self.subTest(key=key):
                for data, identity in ((dict(factory(), **{key: value}), None),
                                       (factory(), dict(capture(), **{key: value}))):
                    with self.assertRaises(PreflightError):
                        check(data, identity)

    def test_fixture_promotion_rejected(self):
        for key in ("fixture_identity", "signature_present", "product_msix"):
            with self.subTest(key=key), self.assertRaises(PreflightError):
                item = factory()
                item[key] = True
                check(item)
        with self.assertRaises(PreflightError):
            check(factory(), dict(capture(), fixture_only=True))

    def test_no_missing_identity_can_be_claimed(self):
        with self.assertRaises(PreflightError):
            check(factory(), {"store_id": "9N95J2T57B41"})

if __name__ == "__main__":
    unittest.main()
