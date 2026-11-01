"""Ensure independently re-downloaded Factory ZIP receipt matches the Sentinel handoff."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "handoffs/prism-sentinel-factory-live-recheck-20261102.json"
HANDOFF = ROOT / "handoffs/prism-sentinel-qa-consumer-20261102.json"


class TestSentinelLiveFactoryReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = json.loads(RECEIPT.read_text(encoding="utf-8"))
        cls.h = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_real_zip_correlates_with_handoff(self):
        r, h = self.r, self.h
        self.assertEqual(r["receipt_type"], "GAME_3D_LIVE_FACTORY_ARCHIVE_RECHECK")
        self.assertEqual(r["source"]["sha"], h["source_sha"])
        self.assertEqual(r["source"]["request_id"], h["request_id"])
        self.assertEqual(r["source"]["factory_build_head"], h["factory_build_head"])
        self.assertEqual(r["artifact"]["workflow_run_id"], h["factory"]["run_id"])
        self.assertEqual(r["artifact"]["artifact_id"], h["factory"]["artifact_id"])
        self.assertEqual(r["members"]["candidate.exe"]["sha256"], h["factory"]["exe_sha256"])
        self.assertEqual(r["members"]["candidate.pck"]["sha256"], h["factory"]["pck_sha256"])
        self.assertEqual(r["artifact"]["archive_sha256"],
                         "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c")
        self.assertTrue(r["zip"]["crc_test_passed"])
        self.assertFalse(r["zip"]["symlink_members_present"])

    def test_no_legacy_or_fixture_promotion(self):
        r, h = self.r, self.h
        self.assertEqual(r["legacy_provisioner_discrimination"]["legacy_pck_sha256"],
                         h["newer_20261101_workflow"]["pck_sha256"])
        self.assertFalse(r["legacy_provisioner_discrimination"]["legacy_promotable_to_sentinel"])
        self.assertFalse(r["downstream"]["historical_identity_rebound_to_sentinel"])
        self.assertFalse(r["downstream"]["unsigned_qa_fixture_is_store_package"])
        for key in ("official_identity_cas", "package_version", "signed_product_msix",
                    "windows_all_auto_intake", "product_e2e"):
            self.assertEqual(r["downstream"][key], "HOLD")
        self.assertFalse(r["downstream"]["store_submission_allowed"])


if __name__ == "__main__":
    unittest.main()
