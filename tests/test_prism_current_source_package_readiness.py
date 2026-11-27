"""Regression tests for the append-only current Prism package handoff."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from prism_current_source_package_readiness import HandoffError, validate


HANDOFF_PATH = (
    Path(__file__).resolve().parents[1]
    / "handoffs/prism-route-3d-current-source-package-readiness-20261128.json"
)


class CurrentSourcePackageReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handoff = json.loads(HANDOFF_PATH.read_text(encoding="utf-8"))

    def test_exact_current_source_and_request_are_pinned(self):
        result = validate(self.handoff)
        self.assertEqual(result["status"], "CURRENT_SOURCE_PACKAGE_HANDOFF_VERIFIED_NOT_PRODUCT")
        self.assertEqual(
            result["source_sha"],
            "b03ce7b16c3f75c04fe20fdda224c45849eeba0d",
        )
        self.assertEqual(result["request_id"], "3d-prism-route-3d-b03ce7b16c3f")

    def test_factory_artifact_and_real_exe_pck_digests_are_pinned(self):
        result = validate(self.handoff)
        self.assertEqual(result["factory_artifact_id"], 14797309778)
        self.assertEqual(
            result["factory_zip_sha256"],
            "e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac",
        )
        self.assertEqual(
            self.handoff["factory_export"]["members"]["candidate.exe"]["sha256"],
            "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13",
        )
        self.assertEqual(
            self.handoff["factory_export"]["members"]["candidate.pck"]["sha256"],
            "b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666",
        )

    def test_stale_source_or_request_is_rejected(self):
        for field, value in (
            ("sha", "e432d94ed0db22878f61f1a8af140d7d7de2288f"),
            ("factory_build_head", "1" * 40),
            ("request_id", "3d-prism-route-3d-e432d94ed0db"),
        ):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.handoff)
                bad["source"][field] = value
                with self.assertRaises(HandoffError):
                    validate(bad)

    def test_old_pr22_pr23_artifact_cannot_replace_current_factory_artifact(self):
        bad = copy.deepcopy(self.handoff)
        bad["factory_export"]["artifact_id"] = 13180284133
        with self.assertRaisesRegex(HandoffError, "Factory artifact mismatch"):
            validate(bad)

    def test_wrong_factory_zip_or_member_digest_is_rejected(self):
        bad_zip = copy.deepcopy(self.handoff)
        bad_zip["factory_export"]["archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(HandoffError, "Factory ZIP digest mismatch"):
            validate(bad_zip)

        bad_member = copy.deepcopy(self.handoff)
        bad_member["factory_export"]["members"]["candidate.pck"]["sha256"] = "1" * 64
        with self.assertRaisesRegex(HandoffError, "Factory member SHA mismatch"):
            validate(bad_member)

    def test_qa_consumer_must_be_the_exact_pr19_head(self):
        bad = copy.deepcopy(self.handoff)
        bad["independent_qa"]["exact_head"] = "75a369d42629b956f0b2c15b0509b7b4038bf709"
        with self.assertRaisesRegex(HandoffError, "QA exact HEAD mismatch"):
            validate(bad)

    def test_package_preflight_must_stack_on_exact_pr19_head(self):
        bad = copy.deepcopy(self.handoff)
        bad["package_preflight"]["base_pr19_head"] = "1" * 40
        with self.assertRaisesRegex(HandoffError, "preflight base mismatch"):
            validate(bad)

    def test_registration_rejects_gdk_and_non_game_routes(self):
        for route in ("GDK_GAME", "MSIX_OR_PWA_APP", "EXE_OR_MSI_APP"):
            with self.subTest(route=route):
                bad = copy.deepcopy(self.handoff)
                bad["registration"]["type"] = route
                with self.assertRaisesRegex(HandoffError, "registration route mismatch"):
                    validate(bad)

    def test_payload_layout_keeps_exe_and_external_pck_side_by_side(self):
        result = validate(self.handoff)
        self.assertFalse(result["package_build_allowed"])
        mapping = self.handoff["package_layout"]["payload_mapping"]
        self.assertEqual(
            [x["package_path"] for x in mapping],
            [
                "VFS/ProgramFilesX64/PrismRoute3D/candidate.exe",
                "VFS/ProgramFilesX64/PrismRoute3D/candidate.pck",
            ],
        )

    def test_missing_official_store_assets_cannot_be_fabricated(self):
        assets = self.handoff["package_layout"]["required_store_assets"]
        self.assertEqual(len(assets), 3)
        self.assertTrue(all(x["source_path"] is None for x in assets))
        bad = copy.deepcopy(self.handoff)
        bad["package_layout"]["required_store_assets"][0]["source_path"] = "generated/logo.png"
        with self.assertRaisesRegex(HandoffError, "unverified Store asset source"):
            validate(bad)

    def test_authoritative_package_version_remains_missing_and_fail_closed(self):
        result = validate(self.handoff)
        self.assertEqual(result["authoritative_package_version"], "HOLD")
        bad = copy.deepcopy(self.handoff)
        bad["version_gate"]["authoritative_package_version"] = "1.0.0.0"
        with self.assertRaisesRegex(HandoffError, "Package Version must remain"):
            validate(bad)

    def test_historical_identity_is_not_rebound_and_36_ledger_is_untouched(self):
        result = validate(self.handoff)
        self.assertEqual(result["identity_rebind"], "HOLD")
        bad = copy.deepcopy(self.handoff)
        bad["identity_gate"]["identity_rebind_or_cas_performed"] = True
        with self.assertRaisesRegex(HandoffError, "Identity or 36-owner ledger was mutated"):
            validate(bad)

    def test_makeappx_is_read_only_and_microsoft_signed(self):
        capability = self.handoff["makeappx_capability"]
        self.assertEqual(capability["authenticode_status"], "Valid")
        self.assertIn("Microsoft Corporation", capability["signer_subject"])
        self.assertFalse(capability["makeappx_pack_invoked"])
        bad = copy.deepcopy(self.handoff)
        bad["makeappx_capability"]["makeappx_pack_invoked"] = True
        with self.assertRaisesRegex(HandoffError, "MakeAppx package creation must remain false"):
            validate(bad)

    def test_makeappx_signature_must_not_be_substituted(self):
        bad = copy.deepcopy(self.handoff)
        bad["makeappx_capability"]["authenticode_status"] = "NotSigned"
        with self.assertRaisesRegex(HandoffError, "MakeAppx Microsoft signature mismatch"):
            validate(bad)

    def test_physical_qa_stays_zero_of_six_and_zero_of_thirty_six(self):
        result = validate(self.handoff)
        self.assertEqual(result["physical_windows_qa"], "DEFERRED_LOCAL_GATE")
        bad = copy.deepcopy(self.handoff)
        bad["physical_qa"]["screenshots_captured"] = 36
        bad["physical_qa"]["status"] = "PASS"
        with self.assertRaisesRegex(HandoffError, "physical Windows QA cannot be promoted"):
            validate(bad)

    def test_product_msix_signing_and_store_submission_remain_false(self):
        result = validate(self.handoff)
        self.assertFalse(result["sale_ready"])
        self.assertFalse(result["store_submission_allowed"])
        for key in ("product_msix_created", "product_msix_signed", "store_submission_allowed"):
            bad = copy.deepcopy(self.handoff)
            bad["controls"][key] = True
            with self.subTest(key=key):
                with self.assertRaises(HandoffError):
                    validate(bad)


if __name__ == "__main__":
    unittest.main()
