"""The checked-in live byte receipt is a HOLD handoff, not Store approval."""
import json
from pathlib import Path
import unittest

from prism_sentinel_live_zip_handoff import PINNED, LEGACY_PCK

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "handoffs/prism-sentinel-live-zip-check-only-20261102-0629-jst.json"


class TestLiveReceiptContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    def test_pinned_real_zip_evidence(self):
        r = self.receipt
        for field in ("source_sha", "request_id", "factory_build_head"):
            self.assertEqual(r[field], PINNED["source_sha"] if field != "request_id"
                             else PINNED["request_id"])
        self.assertEqual(r["factory_run_id"], PINNED["factory_run_id"])
        self.assertEqual(r["factory_artifact_id"], PINNED["artifact_id"])
        self.assertEqual(r["archive_sha256"], PINNED["archive_sha256"])
        self.assertEqual(r["archive_size_bytes"], PINNED["archive_size"])
        self.assertEqual(r["archive_expires_at_utc"], PINNED["expires_at"])
        self.assertTrue(r["archive_bytes_verified_this_run"])
        self.assertTrue(r["zip_crc_pass"])
        self.assertTrue(r["manifest_correlated"])
        for name, (size, digest) in PINNED["members"].items():
            self.assertEqual(r["members"][name], {"size_bytes": size, "sha256": digest})
        self.assertNotEqual(r["members"]["candidate.pck"]["sha256"], LEGACY_PCK)
        self.assertFalse(r["legacy_pck_matches_sentinel"])

    def test_no_unauthorized_store_claim(self):
        r = self.receipt
        self.assertEqual(r["registration_type"], "MSIX_OR_PWA_GAME")
        self.assertEqual(r["partner_center_selection"], "MSIX or PWA game")
        self.assertFalse(r["historical_identity_rebound_to_sentinel"])
        self.assertFalse(r["unsigned_qa_fixture_is_product"])
        self.assertFalse(r["store_submission_allowed"])
        self.assertFalse(r["second_3d_product_allowed"])
        for key in ("official_identity_cas", "approved_package_version",
                    "signed_product_msix", "windows_all_auto_intake", "product_e2e"):
            self.assertEqual(r[key], "HOLD")


if __name__ == "__main__":
    unittest.main()
