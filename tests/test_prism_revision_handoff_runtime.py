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
            ("immutable_original_provenance.identity_reference_commit", "f" * 40),
            ("gates.factory_export", "PASS"),
            ("gates.godot_windows_export", "PASS"),
            ("gates.exe_pck_provisioner", "PASS"),
            ("gates.pre_identity", "PASS"),
            ("gates.registration_type", "GDK_GAME"),
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

    def test_duplicate_identity_field_does_not_pass_set_equality(self):
        changed = copy.deepcopy(self.h)
        changed["user_id_request"]["required_fields"].append("store_id")
        with self.assertRaisesRegex(RevisionHandoffError, "missing official Identity request"):
            validate_revision_handoff(changed, now=self.observed + timedelta(seconds=1))

    def test_missing_historical_identity_commit_fails_closed(self):
        changed = copy.deepcopy(self.h)
        del changed["immutable_original_provenance"]["identity_reference_commit"]
        with self.assertRaisesRegex(RevisionHandoffError, "historical Identity"):
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


class PrismGithubMetadataTests(unittest.TestCase):
    """Offline mock of GitHub's documented run/artifact response shapes."""

    @classmethod
    def setUpClass(cls):
        cls.h = json.loads(HANDOFF.read_text(encoding="utf-8"))
        cls.observed = datetime.fromisoformat(
            cls.h["evidence_observed_at"].replace("Z", "+00:00"))

    def make_api(self):
        runs, artifacts = {}, {}
        for kind, item in self.h["evidence"].items():
            repo = ("shihuiarenjinba-png/3d-game-factory" if kind == "factory"
                    else "shihuiarenjinba-png/Repository-Provisioner-3D")
            branch = ("codex/prism-route-trap-tension-20261029" if kind == "factory"
                      else "codex/e2e-belt-connection-20261027")
            key = (repo, item["run_id"])
            repository_id = (1434223918 if kind == "factory" else 1434261585)
            workflow_path, workflow_id = {
                "factory": (".github/workflows/prism-route-canary-export.yml", 399058278),
                "provisioner_pre": (".github/workflows/prism-revision-provisioner.yml", 400477810),
                "unsigned_makeappx": (".github/workflows/prism-revision-makeappx.yml", 400479598),
                "independent_pck_diagnostic": (".github/workflows/canary-live-provenance.yml", 399059609),
            }[kind]
            runs[key] = {
                "id": item["run_id"], "status": "completed",
                "conclusion": "success", "event": "push",
                "path": workflow_path, "workflow_id": workflow_id,
                "head_sha": item["run_head_sha"], "head_branch": branch,
                "repository": {"id": repository_id},
                "head_repository": {"id": repository_id},
            }
            artifacts.setdefault(key, []).append({
                "id": item["artifact_id"], "name": item["artifact_name"],
                "size_in_bytes": item["archive_bytes"],
                "digest": item["archive_digest"], "expired": False,
                "expires_at": item["expires_at"],
                "workflow_run": {
                    "id": item["run_id"], "head_sha": item["run_head_sha"],
                    "head_branch": branch, "repository_id": repository_id,
                    "head_repository_id": repository_id,
                },
            })
        return runs, artifacts

    def check(self, runs, artifacts):
        from prism_revision_handoff_contract import verify_github_metadata
        return verify_github_metadata(
            self.h, now=self.observed + timedelta(seconds=1),
            fetch_run=lambda repo, run_id: runs[(repo, run_id)],
            fetch_artifacts=lambda repo, run_id: artifacts[(repo, run_id)],
        )

    def test_api_metadata_match_remains_hold(self):
        runs, artifacts = self.make_api()
        receipt = self.check(runs, artifacts)
        self.assertEqual(receipt["status"],
                         "GITHUB_METADATA_MATCH_HOLD_PAYLOAD_NOT_VERIFIED")
        self.assertEqual(len(receipt["github_metadata_checked"]), 4)
        self.assertIs(receipt["artifact_zip_bytes_verified"], False)
        self.assertIs(receipt["store_submission_allowed"], False)
        self.assertEqual(receipt["product_e2e"], "HOLD")

    def test_live_api_drift_rejected(self):
        repo = "shihuiarenjinba-png/Repository-Provisioner-3D"
        item = self.h["evidence"]["provisioner_pre"]
        key = (repo, item["run_id"])
        cases = [
            ("failed run", lambda r, a: r[key].update(conclusion="failure")),
            ("wrong run head", lambda r, a: r[key].update(head_sha="f" * 40)),
            ("unsafe branch", lambda r, a: r[key].update(head_branch="main")),
            ("unexpected event", lambda r, a: r[key].update(event="pull_request")),
            ("wrong workflow path", lambda r, a: r[key].update(path=".github/workflows/ci.yml")),
            ("wrong workflow id", lambda r, a: r[key].update(workflow_id=999999)),
            ("missing workflow identity", lambda r, a: r[key].pop("workflow_id")),
            ("boolean workflow id", lambda r, a: r[key].update(workflow_id=True)),
            ("wrong run repository", lambda r, a: r[key]["repository"].update(id=999999)),
            ("wrong run head repository", lambda r, a: r[key]["head_repository"].update(id=999999)),
            ("missing run repository", lambda r, a: r[key].pop("repository")),
            ("wrong artifact parent repository", lambda r, a: a[key][0]["workflow_run"].update(repository_id=999999)),
            ("same forged artifact repository IDs", lambda r, a: a[key][0]["workflow_run"].update(repository_id=999999, head_repository_id=999999)),
            ("missing artifact", lambda r, a: a[key].clear()),
            ("wrong archive hash", lambda r, a: a[key][0].update(digest="sha256:" + "f" * 64)),
            ("wrong archive size", lambda r, a: a[key][0].update(size_in_bytes=1)),
            ("expired artifact", lambda r, a: a[key][0].update(expired=True)),
            ("wrong artifact name", lambda r, a: a[key][0].update(name="other")),
            ("wrong artifact run", lambda r, a: a[key][0]["workflow_run"].update(id=1)),
            ("wrong artifact head", lambda r, a: a[key][0]["workflow_run"].update(head_sha="f" * 40)),
            ("fork provenance", lambda r, a: a[key][0]["workflow_run"].update(head_repository_id=12346)),
            ("expiry drift", lambda r, a: a[key][0].update(expires_at="2026-11-04T00:00:00Z")),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                runs, artifacts = self.make_api()
                mutate(runs, artifacts)
                with self.assertRaises(RevisionHandoffError):
                    self.check(runs, artifacts)

    def test_api_failure_fails_closed(self):
        runs, artifacts = self.make_api()
        with self.assertRaisesRegex(RevisionHandoffError, "GitHub API unavailable"):
            from prism_revision_handoff_contract import verify_github_metadata
            verify_github_metadata(
                self.h, now=self.observed + timedelta(seconds=1),
                fetch_run=lambda repo, run_id: (_ for _ in ()).throw(OSError("offline")),
                fetch_artifacts=lambda repo, run_id: artifacts[(repo, run_id)],
            )



if __name__ == "__main__":
    unittest.main()
