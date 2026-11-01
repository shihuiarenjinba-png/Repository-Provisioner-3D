"""The newest original-source artifacts must not be substituted for Sentinel."""
import copy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism_20261101_source_gate import (
    ANCHORS, ORIGINAL, RECEIPT, SENTINEL, SourceGateError, classify, main,
)


class LatestPrismArtifactDiscriminationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    def select(self, stage="unsigned_msix", artifact_id=12961735943, source=SENTINEL, receipt=None):
        return classify(self.receipt if receipt is None else receipt, stage=stage,
                        artifact_id=artifact_id, expected_source_sha=source)

    def test_all_three_sentinel_stages_remain_hold_only(self):
        for stage, role in (("factory", "factory"), ("pre", "sentinel_pre"),
                            ("unsigned_msix", "sentinel_unsigned_qa")):
            with self.subTest(stage=stage):
                result = self.select(stage, ANCHORS[role][0])
                self.assertEqual(result["source_sha"], SENTINEL)
                self.assertFalse(result["live_github_authentication"])
                self.assertFalse(result["official_identity_cas_verified"])
                self.assertFalse(result["signed_msix_verified"])
                self.assertFalse(result["windows_all_auto_intake_verified"])
                self.assertEqual(result["product_e2e"], "HOLD")
                self.assertFalse(result["store_submission_allowed"])

    def test_newer_original_pre_and_unsigned_msix_are_not_sentinel(self):
        for stage, role in (("pre", "new_legacy_pre"),
                            ("unsigned_msix", "new_legacy_unsigned_qa")):
            with self.subTest(stage=stage):
                with self.assertRaisesRegex(SourceGateError, "another source or stage"):
                    self.select(stage, ANCHORS[role][0])

    def test_matching_engine_exe_does_not_override_pck_mismatch(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["artifact_checks"]["new_legacy_unsigned_qa"]["pck_matches_sentinel_factory"] = True
        with self.assertRaisesRegex(SourceGateError, "legacy source discrimination"):
            self.select(receipt=receipt)

    def test_legacy_request_or_source_cannot_be_relabelled(self):
        for key, value in (("evidence_source_sha", SENTINEL),
                           ("evidence_request_id", "3d-prism-route-3d-e432d94ed0db")):
            with self.subTest(key=key):
                receipt = copy.deepcopy(self.receipt)
                receipt["artifact_checks"]["new_legacy_unsigned_qa"][key] = value
                with self.assertRaisesRegex(SourceGateError, "legacy source discrimination"):
                    self.select(receipt=receipt)

    def test_rewritten_archive_sha_or_id_is_not_authoritative(self):
        for key, value in (("archive_sha256", "a" * 64), ("artifact_id", 12961735943)):
            with self.subTest(key=key):
                receipt = copy.deepcopy(self.receipt)
                receipt["artifact_checks"]["new_legacy_unsigned_qa"][key] = value
                with self.assertRaisesRegex(SourceGateError, "artifact anchor drift"):
                    self.select(receipt=receipt)

    def test_source_and_stage_mismatch_fail_closed(self):
        with self.assertRaisesRegex(SourceGateError, "not pinned"):
            self.select(source=ORIGINAL)
        with self.assertRaisesRegex(SourceGateError, "unknown stage"):
            self.select(stage="signed_msix")

    def test_unapproved_identity_or_store_status_cannot_be_promoted(self):
        for key, value in (("official_identity_cas", "PASS"),
                           ("signed_msix", "PASS"),
                           ("windows_all_auto_intake", "PASS"),
                           ("store_submission_allowed", True)):
            with self.subTest(key=key):
                receipt = copy.deepcopy(self.receipt)
                receipt["decision"][key] = value
                with self.assertRaisesRegex(SourceGateError, "unsafe downstream"):
                    self.select(receipt=receipt)

    def test_cli_duplicate_json_returns_hold(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--receipt", str(path), "--stage", "factory",
                             "--artifact-id", "12909162367", "--source-sha", SENTINEL])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
