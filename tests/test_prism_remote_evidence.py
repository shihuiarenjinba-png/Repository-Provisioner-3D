"""Regression tests for remote metadata correlation (not an authentication claim)."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from partner_center_handoff_contract import HandoffContractError
from prism_remote_evidence import verify_remote_snapshot

HANDOFF = Path(__file__).resolve().parents[1] / "handoffs" / (
    "prism-route-3d-partner-center-product-creation.json"
)
NOW = datetime(2026, 10, 29, 0, 0, tzinfo=timezone.utc)


def _run(evidence, branch, head):
    return {"id": evidence["run_id"], "head_sha": head,
            "head_branch": branch, "status": "completed", "conclusion": "success"}


def _artifact(evidence, branch, head):
    return {"id": evidence["artifact_id"], "name": evidence["artifact_name"],
            "expired": False, "size_in_bytes": evidence["artifact_archive_size_bytes"],
            "digest": evidence["artifact_archive_digest"],
            "expires_at": evidence["artifact_expires_at"],
            "workflow_run": {"id": evidence["run_id"], "head_sha": head,
                             "head_branch": branch}}


class RemoteEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handoff = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def remote(self):
        h = self.handoff
        factory = h["factory_export_evidence"]
        pre = h["provisioner_pre_identity_evidence"]
        qa = h["real_makeappx_qa_evidence"]
        fb = "codex/3d-canary-prism-route-20261028"
        pb = "codex/e2e-belt-connection-20261027"
        return {
            "factory_run": _run(factory, fb, h["source_sha"]),
            "factory_artifact": _artifact(factory, fb, h["source_sha"]),
            "pre_run": _run(pre, pb, pre["run_head_sha"]),
            "pre_artifact": _artifact(pre, pb, pre["run_head_sha"]),
            "qa_run": _run(qa, pb, qa["run_head_sha"]),
            "qa_artifact": _artifact(qa, pb, qa["run_head_sha"]),
            "pck_artifact": _artifact(h["independent_pck_diagnostic_evidence"],
                                      pb, pre["run_head_sha"]),
            "factory_compare": {
                "status": "ahead", "ahead_by": 1, "behind_by": 0,
                "base_commit": {"sha": h["source_sha"]},
                "merge_base_commit": {"sha": h["source_sha"]},
                "total_commits": 1,
                "commits": [{"sha": h["observed_factory_branch_head"]}],
                "files": [{"filename": "products/prism-route-3d/store/approved-identity.json",
                           "status": "added", "previous_filename": None}],
            },
        }

    def test_valid_api_metadata_still_does_not_promote_product(self):
        receipt = verify_remote_snapshot(self.handoff, self.remote(), now_utc=NOW)
        self.assertEqual(receipt["metadata_comparison"],
                         "PASS_CALLER_SUPPLIED_API_RESPONSES")
        self.assertEqual(receipt["product_e2e"], "HOLD")
        self.assertIs(receipt["pck_payload_bytes_verified_by_this_check"], False)
        for field in ("zip_bytes_verified_by_this_check",
                      "partner_center_identity_verified", "cas_receipt_verified",
                      "signed_msix_verified", "windows_all_auto_intake_verified"):
            self.assertIs(receipt[field], False)

    def test_tampered_remote_fields_fail_closed(self):
        cases = (
            ("factory_run", "head_sha", "f" * 40),
            ("factory_run", "conclusion", "failure"),
            ("pre_run", "head_branch", "main"),
            ("pre_artifact", "digest", "sha256:" + "f" * 64),
            ("pre_artifact", "size_in_bytes", 1),
            ("pre_artifact", "expired", True),
            ("qa_artifact", "id", 123),
            ("pck_artifact", "id", 123),
            ("pck_artifact", "digest", "sha256:" + "f" * 64),
            ("pck_artifact", "expired", True),
            ("qa_artifact", "name", "prism-route-3d-provisioner-pre-identity"),
            ("qa_artifact", "expires_at", "2026-10-28T00:00:00Z"),
            ("factory_compare", "ahead_by", 2),
        )
        for section, field, value in cases:
            with self.subTest(section=section, field=field):
                data = self.remote()
                data[section][field] = value
                with self.assertRaises(HandoffContractError):
                    verify_remote_snapshot(self.handoff, data, now_utc=NOW)

    def test_parent_run_mismatch_and_extra_compare_file_fail_closed(self):
        for section in ("factory_artifact", "pre_artifact", "qa_artifact", "pck_artifact"):
            with self.subTest(section=section):
                data = self.remote()
                data[section]["workflow_run"]["head_sha"] = "f" * 40
                with self.assertRaises(HandoffContractError):
                    verify_remote_snapshot(self.handoff, data, now_utc=NOW)
        data = self.remote()
        data["factory_compare"]["files"].append({"filename": "project.godot"})
        with self.assertRaises(HandoffContractError):
            verify_remote_snapshot(self.handoff, data, now_utc=NOW)

    def test_identity_only_compare_must_match_exact_commit_and_file_status(self):
        cases = (
            ("merge_base_commit", {"sha": "f" * 40}),
            ("total_commits", 2),
            ("commits", [{"sha": "f" * 40}]),
            ("commits", []),
            ("files", [{"filename": "products/prism-route-3d/store/approved-identity.json",
                        "status": "modified", "previous_filename": None}]),
            ("files", [{"filename": "products/prism-route-3d/store/approved-identity.json",
                        "status": "added", "previous_filename": "old.json"}]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                data = self.remote()
                data["factory_compare"][field] = value
                with self.assertRaises(HandoffContractError):
                    verify_remote_snapshot(self.handoff, data, now_utc=NOW)

    def test_missing_expired_or_untrusted_input_rejected(self):
        data = self.remote()
        del data["pck_artifact"]
        with self.assertRaises(HandoffContractError):
            verify_remote_snapshot(self.handoff, data, now_utc=NOW)
        with self.assertRaisesRegex(HandoffContractError, "expired"):
            verify_remote_snapshot(self.handoff, self.remote(),
                                   now_utc=datetime(2026, 11, 6, tzinfo=timezone.utc))
        with self.assertRaisesRegex(HandoffContractError, "timezone-aware"):
            verify_remote_snapshot(self.handoff, self.remote(),
                                   now_utc=datetime(2026, 10, 29))


if __name__ == "__main__":
    unittest.main()
