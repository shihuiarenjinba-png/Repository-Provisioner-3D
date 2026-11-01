"""Regression: historical Prism Partner Center Identity cannot approve Sentinel."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism_20261101_source_gate import ANCHORS
from prism_sentinel_identity_lineage import (
    HISTORICAL_REQUEST, HISTORICAL_SOURCE, SENTINEL_REQUEST, SENTINEL_SOURCE,
    IdentityLineageError, _read, inspect_lineage, main,
)


def sample():
    request = {
        "handoff_type": "GAME_3D_USER_ID_REQUEST", "product_name": "Prism Route 3D",
        "slug": "prism-route-3d", "source_sha": SENTINEL_SOURCE,
        "schema_version": "1.0",
        "factory_run_id": ANCHORS["factory"][1],
        "factory_artifact_id": ANCHORS["factory"][0],
        "artifact_freshness_recheck_required_before_consumption": True,
        "request_id": SENTINEL_REQUEST, "factory_build_head": SENTINEL_SOURCE,
        "registration_type": "MSIX_OR_PWA_GAME", "partner_center_selection": "MSIX or PWA game",
        "packaging_strategy": "GODOT_WINDOWS_EXE_PCK_TO_MAKEAPPX_STANDARD_MSIX",
        "allow_local_product_creation": False,
        "status": "USER_ID_REQUEST_REVERIFY_EXISTING_PRODUCT",
        "source_repository": "shihuiarenjinba-png/3d-game-factory",
        "source_branch": "codex/prism-route-trap-tension-20261029",
        "partner_center_product_status": "UNRECONCILED_MANUAL_OBSERVATIONS",
        "official_identity_capture_status": "NOT_INDEPENDENTLY_AUTHENTICATED",
        "approved_package_version": None,
        "signed_post_identity_msix_sha256": None,
        "windows_all_auto_intake_receipt": None,
        "xbox_title_id_scid_msa_app_id_required": False,
        "local_windows_gui_gpu_install": "DEFERRED_LOCAL_GATE",
        "official_identity_fields_required": {k: None for k in (
            "store_id", "reserved_display_name", "package_identity_name", "publisher",
            "publisher_display_name", "pfn", "package_sid")},
        "historical_reference_not_current_approval": {
            "source_sha": HISTORICAL_SOURCE, "verified_for_new_source": False,
            "identity_reference_commit": "11417b75636ee18816028ffd5221884c4c9a9836",
            "store_id": "9N95J2T57B41"},
        "identity_cas_handoff": {
            "target": "products/prism-route-3d/store/approved-identity.json",
            "required_new_source_sha": SENTINEL_SOURCE,
            "required_new_request_id": SENTINEL_REQUEST,
            "official_capture_receipt": None, "new_source_cas_receipt": None, "status": "HOLD"},
        "product_e2e": "HOLD", "store_submission_allowed": False,
    }
    inherited = {
        "reviewed": True, "source": "partner_center", "slug": "prism-route-3d",
        "request_id": HISTORICAL_REQUEST, "source_sha": HISTORICAL_SOURCE,
        "verified_source_sha": HISTORICAL_SOURCE, "expected_head_sha": HISTORICAL_SOURCE,
        "store_id": "9N95J2T57B41", "reserved_display_name": "Prism Route 3D",
        "name": "OkinawaDesktopTools.PrismRoute3D",
        "publisher_display_name": "Okinawa Desktop Tools", "publisher": "CN=reference",
        "package_family_name": "OkinawaDesktopTools.PrismRoute3D_reference",
        "package_sid": "S-1-15-2-reference",
    }
    return request, inherited


class IdentityLineageTests(unittest.TestCase):
    def test_reviewed_true_is_still_hold(self):
        req, old = sample()
        result = inspect_lineage(req, old)
        self.assertEqual(result["status"], "HOLD_HISTORICAL_IDENTITY_NOT_SENTINEL_CAS")
        self.assertFalse(result["new_source_cas_verified"])
        self.assertFalse(result["store_submission_allowed"])

    def test_source_request_and_reviewed_spoof_rejected(self):
        for target, field, value in (
            ("request", "source_sha", HISTORICAL_SOURCE),
            ("request", "request_id", HISTORICAL_REQUEST),
            ("identity", "source_sha", SENTINEL_SOURCE),
            ("identity", "verified_source_sha", SENTINEL_SOURCE),
            ("identity", "request_id", SENTINEL_REQUEST),
            ("identity", "reviewed", False),
        ):
            with self.subTest(target=target, field=field):
                req, old = sample()
                (req if target == "request" else old)[field] = value
                with self.assertRaises(IdentityLineageError):
                    inspect_lineage(req, old)

    def test_fake_cas_and_official_fields_rejected(self):
        for field, value in (("new_source_cas_receipt", {"approved": True}),
                             ("official_capture_receipt", {"reviewed": True}),
                             ("status", "PASS")):
            with self.subTest(field=field):
                req, old = sample()
                req["identity_cas_handoff"][field] = value
                with self.assertRaises(IdentityLineageError):
                    inspect_lineage(req, old)
        req, old = sample()
        req["official_identity_fields_required"]["store_id"] = "9N95J2T57B41"
        with self.assertRaises(IdentityLineageError):
            inspect_lineage(req, old)

    def test_wrong_product_or_missing_identity_field_rejected(self):
        for field, value in (("store_id", "9N0000000000"),
                             ("slug", "another-game"), ("publisher", "")):
            with self.subTest(field=field):
                req, old = sample()
                old[field] = value
                with self.assertRaises(IdentityLineageError):
                    inspect_lineage(req, old)

    def test_fake_package_and_intake_readiness_rejected(self):
        for field, value in (
            ("status", "APPROVED"),
            ("source_branch", "codex/another-game"),
            ("official_identity_capture_status", "AUTHENTICATED"),
            ("partner_center_product_status", "CREATED"),
            ("approved_package_version", "1.0.0.0"),
            ("signed_post_identity_msix_sha256", "0" * 64),
            ("windows_all_auto_intake_receipt", {"accepted": True}),
            ("xbox_title_id_scid_msa_app_id_required", True),
            ("local_windows_gui_gpu_install", "PASS"),
        ):
            with self.subTest(field=field):
                req, old = sample()
                req[field] = value
                with self.assertRaises(IdentityLineageError):
                    inspect_lineage(req, old)

    def test_factory_run_artifact_and_history_substitution_rejected(self):
        for field, value in (
            ("factory_run_id", ANCHORS["sentinel_pre"][1]),
            ("factory_run_id", True),
            ("factory_artifact_id", ANCHORS["sentinel_pre"][0]),
            ("factory_artifact_id", True),
            ("artifact_freshness_recheck_required_before_consumption", False),
            ("schema_version", "2.0"),
        ):
            with self.subTest(field=field, value=value):
                req, old = sample()
                req[field] = value
                with self.assertRaises(IdentityLineageError):
                    inspect_lineage(req, old)
        req, old = sample()
        req["historical_reference_not_current_approval"]["identity_reference_commit"] = "0" * 40
        with self.assertRaises(IdentityLineageError):
            inspect_lineage(req, old)

    def test_real_committed_user_id_request_is_still_hold(self):
        req_path = Path(__file__).resolve().parents[1] / "handoffs" / (
            "prism-route-3d-sentinel-user-id-request-20261101-1127.json"
        )
        req = _read(req_path)
        _, inherited = sample()
        result = inspect_lineage(req, inherited)
        self.assertEqual(result["status"], "HOLD_HISTORICAL_IDENTITY_NOT_SENTINEL_CAS")
        self.assertFalse(result["new_source_cas_verified"])
        self.assertFalse(result["signed_msix_verified"])

    def test_duplicate_and_oversized_json_rejected(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"source_sha":"a","source_sha":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(IdentityLineageError, "duplicate"):
                _read(path)
            path.write_bytes(b" " * 65537)
            with self.assertRaisesRegex(IdentityLineageError, "oversized"):
                _read(path)

    def test_cli_hold_only_and_fail_closed(self):
        req, old = sample()
        with TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "request.json", Path(tmp) / "identity.json"
            a.write_text(json.dumps(req), encoding="utf-8")
            b.write_text(json.dumps(old), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--request", str(a), "--inherited-identity", str(b)])
            self.assertEqual(code, 0)
            self.assertFalse(json.loads(output.getvalue())["store_submission_allowed"])
            b.write_text("{}", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--request", str(a), "--inherited-identity", str(b)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "HOLD_INVALID_IDENTITY_LINEAGE")


if __name__ == "__main__":
    unittest.main()
