"""Negative tests for consume-time Prism revision evidence safety."""
import copy
from datetime import datetime, timedelta
import json
from pathlib import Path
import unittest

from prism_revision_handoff_contract import RevisionHandoffError, validate_revision_handoff

HANDOFF = Path(__file__).resolve().parents[1] / "handoffs/prism-route-3d-sentinel-revision-20261029.json"


class PrismRevisionHandoffRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = json.loads(HANDOFF.read_text(encoding="utf-8"))
        cls.observed = datetime.fromisoformat(cls.h["evidence_observed_at"].replace("Z", "+00:00"))

    def test_real_snapshot_is_hold_not_authorization(self):
        receipt = validate_revision_handoff(self.h, now=self.observed + timedelta(seconds=1))
        self.assertEqual(receipt["status"], "CONTRACT_VALID_HOLD_NOT_AUTHENTICATED")
        self.assertEqual(receipt["product_e2e"], "HOLD")
        self.assertEqual(receipt["github_artifact_authentication"], "REQUIRED_SEPARATELY")

    def test_consumption_rejects_expired_diagnostic(self):
        expiry = datetime.fromisoformat(
            self.h["evidence"]["independent_pck_diagnostic"]["expires_at"].replace("Z", "+00:00"))
        with self.assertRaisesRegex(RevisionHandoffError, "expired artifact"):
            validate_revision_handoff(self.h, now=expiry)
        # Archival inspection remains possible, but must not authorize current bytes.
        receipt = validate_revision_handoff(self.h, now=expiry, require_unexpired=False)
        self.assertEqual(receipt["product_e2e"], "HOLD")

    def test_fail_closed_mutations(self):
        cases = (
            ("request_id", "3d-prism-route-3d-15fdcb52e46e"),
            ("registration_type", "GDK_GAME"),
            ("partner_center_product_status", "NOT_CREATED"),
            ("allow_local_product_creation", True),
            ("identity_status", "IDENTITY_VALIDATED"),
            ("gates.identity_cas", "PASS"),
            ("gates.product_e2e", "PASS"),
            ("controls.store_submission_allowed", True),
            ("evidence.factory.run_head_sha", "a" * 40),
            ("evidence.provisioner_pre.run_head_sha", "b" * 40),
            ("evidence.unsigned_makeappx.signed", True),
            ("evidence.unsigned_makeappx.store_ready", True),
            ("evidence.independent_pck_diagnostic.not_store_payload", False),
            ("evidence.factory.archive_digest", "sha256:" + "z" * 64),
            ("evidence.factory.archive_bytes", True),
            ("evidence.factory.expires_at", "2026-01-01T00:00:00Z"),
            ("immutable_original_provenance.identity_reference_is_new_revision_approval", True),
        )
        for path, value in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.h)
                target = changed
                parts = path.split(".")
                for key in parts[:-1]:
                    target = target[key]
                target[parts[-1]] = value
                with self.assertRaises(RevisionHandoffError):
                    validate_revision_handoff(changed, now=self.observed + timedelta(seconds=1))

    def test_self_consistent_source_rebinding_rejected(self):
        # A substituted revision can satisfy the derived request_id and Factory
        # run HEAD checks; the original approved Sentinel source must still win.
        changed = copy.deepcopy(self.h)
        impostor = "f" * 40
        changed["source_sha"] = impostor
        changed["request_id"] = "3d-prism-route-3d-" + impostor[:12]
        changed["evidence"]["factory"]["run_head_sha"] = impostor
        with self.assertRaisesRegex(RevisionHandoffError, "unapproved Sentinel source revision"):
            validate_revision_handoff(changed, now=self.observed + timedelta(seconds=1))

    def test_naive_clock_rejected(self):
        with self.assertRaisesRegex(RevisionHandoffError, "timezone aware"):
            validate_revision_handoff(self.h, now=datetime(2026, 10, 30))


if __name__ == "__main__":
    unittest.main()
