import base64
import json
from pathlib import Path
import tempfile
import unittest

from identity_only_return import canonical_digest, run_identity_return
from package_identity_provisioner import GitHubReturnClient, ProductConfig

SHA = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"


def queue_job():
    return {
        "request_id": "3d-prism-route-3d-15fdcb52e46e", "product_type": "GAME_3D",
        "source_repository": "shihuiarenjinba-png/3d-game-factory",
        "source_branch": "codex/3d-canary-prism-route-20261028", "source_sha": SHA,
        "slug": "prism-route-3d", "display_name": "Prism Route 3D",
        "registration_type": "MSIX_OR_PWA_GAME", "partner_center_selection": "MSIX or PWA game",
        "status": "PRE_IDENTITY_READY", "artifact_provenance": "REAL_WINDOWS_EXPORT_VERIFIED",
        "expected_exe_sha256": "6" * 64, "factory_build_head": SHA,
    }


def operator_job():
    item = queue_job()
    return {**{key: item[key] for key in (
        "request_id", "source_repository", "source_branch", "source_sha", "slug", "display_name",
        "registration_type", "partner_center_selection")}, "queue_job_digest": canonical_digest(item)}


def receipt(path: Path):
    value = {
        "schema_version": 1, "status": "IDENTITY_CAPTURED__UI_MATCHED_REFERENCE__GITHUB_BOUND",
        "authenticated_partner_center_pass": True, "capture_source": "AUTHENTICATED_PARTNER_CENTER_UI",
        "job_origin": "GITHUB_PRE_IDENTITY_QUEUE", "central_repository": "shihuiarenjinba-png/Windows-all-auto",
        "central_branch": "codex/e2e-belt-connection-20261027", "central_head_sha": "4" * 40,
        "queue_job_digest": canonical_digest(queue_job()), "request_id": queue_job()["request_id"],
        "source_repository": queue_job()["source_repository"], "source_branch": queue_job()["source_branch"],
        "source_sha": SHA, "source_snapshot_path": "C:/snapshot", "source_snapshot_head": SHA,
        "slug": "prism-route-3d", "product_type": "GAME_3D", "registration_type": "MSIX_OR_PWA_GAME",
        "partner_center_selection": "MSIX or PWA game", "display_name": "Prism Route 3D",
        "store_id": "9N95J2T57B41", "reserved_display_name": "Prism Route 3D",
        "identity_name": "OkinawaDesktopTools.PrismRoute3D", "publisher": "CN=Example",
        "publisher_display_name": "Okinawa Desktop Tools",
        "package_family_name": "OkinawaDesktopTools.PrismRoute3D_j8yefg9jgfh58",
        "package_sid": "S-1-15-2-1-2-3-4-5-6-7", "captured_at": "2026-10-28T00:00:00Z",
        "creation_status": "REUSED_EXISTING", "overview_exact_match_count": 1,
        "identity_details_observed": True, "manual_reference_comparison": "MATCH",
        "identity_return_target": "products/prism-route-3d/store/approved-identity.json",
        "package_version_gate": "HOLD", "existing_scheduler_routing_pending": True,
        "cas_applied": False, "store_submitted": False,
    }
    path.write_text(json.dumps(value), encoding="utf-8")


class Api:
    def __init__(self): self.body = None
    def __call__(self, endpoint, body=None, allow_missing=False):
        if endpoint.endswith("git/ref/heads/codex/3d-canary-prism-route-20261028"):
            return {"object": {"sha": SHA}}
        if "contents/products/prism-route-3d/project.godot" in endpoint:
            return {"encoding": "base64", "content": base64.b64encode(b"run/main_scene=x").decode()}
        if "contents/products/prism-route-3d/export_presets.cfg" in endpoint:
            data = b'[preset.0]\nname="Windows Desktop"\nplatform="Windows Desktop"\n'
            return {"encoding": "base64", "content": base64.b64encode(data).decode()}
        if "approved-identity.json" in endpoint:
            return None
        if endpoint == "graphql":
            self.body = body
            return {"data": {"createCommitOnBranch": {"commit": {"oid": "a" * 40, "url": "https://example"}}}}
        raise AssertionError(endpoint)


class IdentityOnlyReturnTests(unittest.TestCase):
    def test_github_wrapped_base64_is_accepted_strictly(self):
        encoded = base64.b64encode(b"run/main_scene=x").decode()
        wrapped = encoded[:8] + "\n" + encoded[8:] + "\n"
        self.assertEqual(
            GitHubReturnClient._decode_content({"encoding": "base64", "content": wrapped}, 100),
            b"run/main_scene=x",
        )

    def test_reuses_single_writer_without_package_version(self):
        cfg = ProductConfig.load(Path(__file__).parents[1] / "config.json")
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "official.json"
            receipt(evidence)
            api = Api()
            result = run_identity_return(
                ledger={"rotation_cohorts": {"three_d_jobs": [queue_job()]}},
                operator_job=operator_job(), receipt_path=evidence, config=cfg, apply=True,
                github=GitHubReturnClient(api),
            )
        self.assertEqual(result["status"], "APPLIED")
        encoded = api.body["variables"]["input"]["fileChanges"]["additions"][0]["contents"]
        approved = json.loads(base64.b64decode(encoded))
        self.assertNotIn("version", approved)
        self.assertEqual(approved["package_version_gate"], "HOLD")
        self.assertEqual(approved["verified_source_sha"], SHA)

    def test_changed_queue_digest_conflicts(self):
        cfg = ProductConfig.load(Path(__file__).parents[1] / "config.json")
        changed = queue_job(); changed["expected_exe_sha256"] = "7" * 64
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "official.json"; receipt(evidence)
            with self.assertRaisesRegex(Exception, "digest changed"):
                run_identity_return(
                    ledger={"rotation_cohorts": {"three_d_jobs": [changed]}},
                    operator_job=operator_job(), receipt_path=evidence, config=cfg, apply=False,
                )

    def test_restart_after_cas_is_existing_verified_without_second_write(self):
        cfg = ProductConfig.load(Path(__file__).parents[1] / "config.json")
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "official.json"; receipt(evidence)
            first_api = Api()
            first = run_identity_return(
                ledger={"rotation_cohorts": {"three_d_jobs": [queue_job()]}},
                operator_job=operator_job(), receipt_path=evidence, config=cfg, apply=True,
                github=GitHubReturnClient(first_api),
            )
            encoded = first_api.body["variables"]["input"]["fileChanges"]["additions"][0]["contents"]

            class ReplayApi(Api):
                def __init__(self):
                    super().__init__(); self.graphql_calls = 0
                def __call__(self, endpoint, body=None, allow_missing=False):
                    if endpoint.endswith("git/ref/heads/codex/3d-canary-prism-route-20261028"):
                        return {"object": {"sha": "a" * 40}}
                    if "approved-identity.json" in endpoint:
                        wrapped = encoded[:76] + "\n" + encoded[76:] + "\n"
                        return {"encoding": "base64", "content": wrapped}
                    if endpoint == "graphql":
                        self.graphql_calls += 1
                    return super().__call__(endpoint, body=body, allow_missing=allow_missing)

            replay_api = ReplayApi()
            replay = run_identity_return(
                ledger={"rotation_cohorts": {"three_d_jobs": [queue_job()]}},
                operator_job=operator_job(), receipt_path=evidence, config=cfg, apply=True,
                github=GitHubReturnClient(replay_api),
            )
        self.assertEqual(first["status"], "APPLIED")
        self.assertEqual(replay["status"], "EXISTING_VERIFIED")
        self.assertEqual(replay_api.graphql_calls, 0)


if __name__ == "__main__":
    unittest.main()
