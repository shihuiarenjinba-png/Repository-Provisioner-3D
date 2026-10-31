"""Negative tests for real Prism provenance and pre-Identity safety gates."""
import copy
import json
from pathlib import Path
import unittest

from partner_center_handoff_contract import HandoffContractError, validate_prism_handoff

HANDOFF = Path(__file__).resolve().parents[1] / "handoffs" / "prism-route-3d-partner-center-product-creation.json"


class StrictCanaryProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid = json.loads(HANDOFF.read_text(encoding="utf-8"))

    def test_current_real_canary_handoff(self):
        validate_prism_handoff(self.valid)

    def test_factory_build_head_cannot_be_forged(self):
        d = copy.deepcopy(self.valid)
        d["factory_build_head"] = "f" * 40
        with self.assertRaisesRegex(HandoffContractError, "Factory run head"):
            validate_prism_handoff(d)

    def test_identity_only_branch_commit_must_match(self):
        d = copy.deepcopy(self.valid)
        d["identity_return_commit_observed"] = "f" * 40
        with self.assertRaisesRegex(HandoffContractError, "Identity return commit"):
            validate_prism_handoff(d)

    def test_factory_run_artifact_and_authenticated_flag(self):
        for field, value in (
            ("run_id", 40640951916),
            ("artifact_id", 12795476436),
            ("artifact_name", "untrusted"),
            ("authenticated_download_verified", False),
            ("authenticated_download_verified", 1),
        ):
            with self.subTest(field=field, value=value):
                d = copy.deepcopy(self.valid)
                d["factory_export_evidence"][field] = value
                with self.assertRaisesRegex(HandoffContractError, "Factory export"):
                    validate_prism_handoff(d)

    def test_pre_and_makeappx_receipts_cannot_be_empty_or_boolean(self):
        for key in ("provisioner_pre_identity_evidence", "real_makeappx_qa_evidence"):
            for field, value in (("run_id", None), ("artifact_id", 0), ("run_id", True)):
                with self.subTest(key=key, field=field, value=value):
                    d = copy.deepcopy(self.valid)
                    d[key][field] = value
                    with self.assertRaisesRegex(HandoffContractError, "execution evidence"):
                        validate_prism_handoff(d)

    def test_unsigned_makeappx_never_promoted_to_signed_store(self):
        for field, value in (
            ("qa_only", False), ("signed", True), ("store_ready", True),
            ("signed", 0), ("qa_only", 1),
        ):
            with self.subTest(field=field, value=value):
                d = copy.deepcopy(self.valid)
                d["real_makeappx_qa_evidence"][field] = value
                with self.assertRaisesRegex(HandoffContractError, "unsigned MakeAppx"):
                    validate_prism_handoff(d)

    def test_repo_write_and_local_qa_controls_are_fail_closed(self):
        for field in ("main_release_write_allowed", "force_push_allowed", "auto_merge_allowed"):
            d = copy.deepcopy(self.valid)
            d["controls"][field] = True
            with self.subTest(field=field), self.assertRaisesRegex(HandoffContractError, "unsafe repository"):
                validate_prism_handoff(d)
        d = copy.deepcopy(self.valid)
        d["controls"]["local_gpu_install_gui"] = "PASS"
        with self.assertRaisesRegex(HandoffContractError, "physical Windows QA"):
            validate_prism_handoff(d)


if __name__ == "__main__":
    unittest.main()
