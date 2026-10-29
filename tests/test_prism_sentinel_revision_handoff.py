"""Fail-closed contract for the single Prism Sentinel revision handoff.

The archived original Identity reference must never silently authorize the
new source, version, signed package, or Windows intake.
"""
import json
from pathlib import Path
import re
import unittest
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "handoffs/prism-route-3d-sentinel-revision-20261029.json"
MAKEAPPX = ROOT / "tests/prism_revision_makeappx.py"


class PrismSentinelRevisionHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = json.loads(HANDOFF.read_text(encoding="utf-8"))
        cls.makeappx = MAKEAPPX.read_text(encoding="utf-8")

    def test_single_product_immutable_source_binding(self):
        h = self.h
        self.assertEqual(h["product"], "Prism Route 3D")
        self.assertEqual(h["slug"], "prism-route-3d")
        self.assertEqual(h["source_branch"], "codex/prism-route-trap-tension-20261029")
        source = h["source_sha"]
        self.assertRegex(source, r"^[0-9a-f]{40}$")
        self.assertEqual(h["request_id"], "3d-prism-route-3d-" + source[:12])
        self.assertIn('SOURCE = "' + source + '"', self.makeappx)
        self.assertIn('REQUEST = "' + h["request_id"] + '"', self.makeappx)
        old = h["immutable_original_provenance"]
        self.assertNotEqual(source, old["source_sha"])
        self.assertFalse(old["identity_reference_is_new_revision_approval"])

    def test_registration_and_identity_fail_closed(self):
        h = self.h
        self.assertEqual(h["registration_type"], "MSIX_OR_PWA_GAME")
        self.assertEqual(h["partner_center_selection"], "MSIX or PWA game")
        self.assertEqual(h["partner_center_product_status"], "UNRECONCILED_MANUAL_OBSERVATIONS")
        self.assertFalse(h["allow_local_product_creation"])
        self.assertEqual(h["identity_status"], "OFFICIAL_CAPTURE_AND_NEW_REVISION_CAS_NOT_PROVEN")
        self.assertEqual(h["identity_rebinding_status"], "HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING")
        self.assertEqual(h["identity_return_target"], "products/prism-route-3d/store/approved-identity.json")
        self.assertFalse(h["user_id_request"]["xbox_fields_required"])
        self.assertEqual(set(h["user_id_request"]["required_fields"]), {
            "store_id", "reserved_display_name", "package_identity_name",
            "publisher", "publisher_display_name", "pfn", "package_sid",
        })
        for key in ("identity_cas", "approved_package_version", "signed_post_identity_msix",
                    "windows_all_auto_intake", "product_e2e"):
            self.assertEqual(h["gates"][key], "HOLD", key)
        self.assertEqual(h["gates"]["local_gpu_install_gui"], "DEFERRED_LOCAL_GATE")
        for key in ("second_3d_product_allowed", "store_submission_allowed",
                    "main_release_write_allowed", "force_push_allowed", "auto_merge_allowed"):
            self.assertFalse(h["controls"][key], key)

    def test_real_artifact_pins_are_distinct_and_not_payload_hashes(self):
        h = self.h
        evidence = h["evidence"]
        self.assertEqual(evidence["factory"]["run_head_sha"], h["source_sha"])
        self.assertEqual(evidence["factory"]["run_id"],
                         int(re.search(r"^RUN = (\\d+)$", self.makeappx, re.MULTILINE).group(1)))
        self.assertEqual(evidence["factory"]["artifact_id"],
                         int(re.search(r"^ARTIFACT = (\\d+)$", self.makeappx, re.MULTILINE).group(1)))
        ids = [item["artifact_id"] for item in evidence.values()]
        self.assertEqual(len(ids), len(set(ids)))
        for name, item in evidence.items():
            self.assertRegex(item["archive_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertGreater(item["archive_bytes"], 0)
            self.assertGreater(item["run_id"], 0)
            self.assertGreater(item["artifact_id"], 0)
            self.assertRegex(item["run_head_sha"], r"^[0-9a-f]{40}$")
            self.assertIsNotNone(datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00")).tzinfo)
        self.assertFalse(evidence["unsigned_makeappx"]["signed"])
        self.assertFalse(evidence["unsigned_makeappx"]["store_ready"])
        self.assertTrue(evidence["independent_pck_diagnostic"]["diagnostic_only"])
        self.assertTrue(evidence["independent_pck_diagnostic"]["not_store_payload"])
        self.assertIn("not EXE/PCK/MSIX payload hashes", h["evidence_observation_scope"])


if __name__ == "__main__":
    unittest.main()
