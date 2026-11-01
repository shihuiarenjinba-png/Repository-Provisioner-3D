"""Keep QA consumer handoff pinned to real Sentinel and historical HOLD roles."""
import json
from pathlib import Path
import unittest

from prism_20261101_source_gate import (
    ANCHORS, EXE_SHA, SENTINEL_PCK, ORIGINAL_PCK,
    SENTINEL, SENTINEL_REQUEST, ORIGINAL, ORIGINAL_REQUEST,
)

HANDOFF = Path(__file__).resolve().parents[1] / "handoffs/prism-sentinel-qa-consumer-20261102.json"


class TestPrismQAConsumerHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_source_factory_request_are_pinned(self):
        h = self.h
        self.assertEqual(h["source_sha"], SENTINEL)
        self.assertEqual(h["factory_build_head"], SENTINEL)
        self.assertEqual(h["request_id"], SENTINEL_REQUEST)
        self.assertEqual(h["registration_type"], "MSIX_OR_PWA_GAME")
        self.assertEqual(h["partner_center_selection"], "MSIX or PWA game")

    def test_real_artifact_roles_are_not_interchangeable(self):
        h = self.h
        for role, name in (("factory", "factory"), ("provisioner_pre", "sentinel_pre"),
                           ("unsigned_qa_fixture", "sentinel_unsigned_qa")):
            self.assertEqual(h[role]["artifact_id"], ANCHORS[name][0])
            self.assertEqual(h[role]["run_id"], ANCHORS[name][1])
        self.assertEqual(h["factory"]["exe_sha256"], EXE_SHA)
        self.assertEqual(h["factory"]["pck_sha256"], SENTINEL_PCK)
        self.assertEqual(h["newer_20261101_workflow"]["source_sha"], ORIGINAL)
        self.assertEqual(h["newer_20261101_workflow"]["request_id"], ORIGINAL_REQUEST)
        self.assertEqual(h["newer_20261101_workflow"]["pck_sha256"], ORIGINAL_PCK)
        self.assertFalse(h["newer_20261101_workflow"]["same_pck_as_sentinel"])
        self.assertFalse(h["newer_20261101_workflow"]["promotable_to_sentinel"])

    def test_fixture_and_historical_identity_are_not_store_ready(self):
        h = self.h
        self.assertEqual(h["unsigned_qa_fixture"]["fixture_identity"], "Example.ThreeD.Fixture")
        self.assertFalse(h["unsigned_qa_fixture"]["signature_present"])
        self.assertFalse(h["unsigned_qa_fixture"]["store_product_msix"])
        self.assertEqual(h["historical_identity"]["source_sha"], ORIGINAL)
        self.assertFalse(h["historical_identity"]["verified_for_sentinel"])
        self.assertEqual(h["identity_return_target"],
                         "products/prism-route-3d/store/approved-identity.json")
        for field in ("official_identity_cas", "package_version",
                      "signed_product_msix", "windows_all_auto_intake", "product_e2e"):
            self.assertEqual(h[field], "HOLD")
        self.assertEqual(h["local_windows_gate"], "DEFERRED_LOCAL_GATE")
        self.assertFalse(h["store_submission_allowed"])
        self.assertFalse(h["second_3d_product_allowed"])


if __name__ == "__main__":
    unittest.main()
