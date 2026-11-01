"""Sentinel USER_ID_REQUEST is operator-facing and cannot approve Store E2E."""
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism_revision_handoff_contract import RevisionHandoffError
from prism_sentinel_user_id_request import (
    REQUIRED_FIELDS, _reject_duplicate_keys, build_user_id_request, main,
)

HANDOFF = (
    Path(__file__).resolve().parents[1]
    / "handoffs/prism-route-3d-sentinel-revision-20261029.json"
)


class SentinelUserIdRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pinned = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_pinned_revision_emits_complete_unapproved_operator_request(self):
        result = build_user_id_request(self.pinned)
        self.assertEqual(result["status"], "USER_ID_REQUEST_REVERIFY_EXISTING_PRODUCT")
        self.assertEqual(result["product_name"], "Prism Route 3D")
        self.assertEqual(result["registration_type"], "MSIX_OR_PWA_GAME")
        self.assertEqual(result["partner_center_selection"], "MSIX or PWA game")
        self.assertEqual(result["source_sha"], "e432d94ed0db22878f61f1a8af140d7d7de2288f")
        self.assertEqual(result["request_id"], "3d-prism-route-3d-e432d94ed0db")
        self.assertEqual(result["factory_build_head"], result["source_sha"])
        self.assertEqual(set(result["official_identity_fields_required"]), set(REQUIRED_FIELDS))
        self.assertTrue(all(v is None for v in result["official_identity_fields_required"].values()))
        self.assertFalse(result["allow_local_product_creation"])
        self.assertFalse(result["xbox_title_id_scid_msa_app_id_required"])
        self.assertFalse(result["historical_reference_not_current_approval"]["verified_for_new_source"])
        self.assertEqual(result["historical_reference_not_current_approval"]["store_id"], "9N95J2T57B41")
        self.assertIsNone(result["identity_cas_handoff"]["new_source_cas_receipt"])
        self.assertEqual(result["identity_cas_handoff"]["status"], "HOLD")
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_committed_user_id_request_matches_generator(self):
        # The handoff consumed by the Windows lane must not silently drift
        # from the pinned source/request or acquire invented Identity fields.
        materialized = (
            Path(__file__).resolve().parents[1]
            / "handoffs/prism-route-3d-sentinel-user-id-request-20261101-1127.json"
        )
        with materialized.open(encoding="utf-8") as stream:
            actual = json.load(stream, object_pairs_hook=_reject_duplicate_keys)
        expected = build_user_id_request(self.pinned)
        self.assertEqual(actual, expected)
        self.assertTrue(all(value is None for value in actual["official_identity_fields_required"].values()))
        self.assertEqual(actual["identity_cas_handoff"]["status"], "HOLD")
        self.assertIsNone(actual["approved_package_version"])
        self.assertIsNone(actual["signed_post_identity_msix_sha256"])
        self.assertIsNone(actual["windows_all_auto_intake_receipt"])
        self.assertFalse(actual["store_submission_allowed"])

    def test_historical_identity_cannot_masquerade_as_new_revision(self):
        bad = copy.deepcopy(self.pinned)
        bad["source_sha"] = bad["immutable_original_provenance"]["source_sha"]
        with self.assertRaises(RevisionHandoffError):
            build_user_id_request(bad)

    def test_unverified_store_reference_drift_is_rejected(self):
        bad = copy.deepcopy(self.pinned)
        bad["existing_store_id_reference_unverified"] = "9N0000000000"
        with self.assertRaisesRegex(RevisionHandoffError, "reference drift"):
            build_user_id_request(bad)

    def test_identity_or_cas_promotion_is_rejected(self):
        for field, value in (
            ("identity_status", "IDENTITY_VALIDATED"),
            ("identity_rebinding_status", "CAS_VERIFIED"),
            ("allow_local_product_creation", True),
        ):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.pinned)
                bad[field] = value
                with self.assertRaises(RevisionHandoffError):
                    build_user_id_request(bad)

    def test_expired_artifacts_do_not_prevent_identity_request(self):
        # Only asking for an Identity is permitted; consumption remains gated.
        later = datetime(2026, 11, 7, tzinfo=timezone.utc)
        result = build_user_id_request(self.pinned, now=later)
        self.assertTrue(result["artifact_freshness_recheck_required_before_consumption"])
        self.assertEqual(result["identity_cas_handoff"]["status"], "HOLD")

    def test_duplicate_input_keys_rejected(self):
        with self.assertRaisesRegex(RevisionHandoffError, "duplicate"):
            json.loads('{"source_sha":"a","source_sha":"b"}',
                       object_pairs_hook=_reject_duplicate_keys)

    def test_invalid_cli_input_returns_machine_readable_hold(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.json"
            path.write_text("{}", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["--handoff", str(path)])
        self.assertEqual(exit_code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "HOLD_INVALID_USER_ID_REQUEST_INPUT")
        self.assertIs(result["store_submission_allowed"], False)


if __name__ == "__main__":
    unittest.main()
