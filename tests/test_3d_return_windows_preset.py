"""A 3D Identity return must not approve a product lacking Windows export settings."""
import base64
from pathlib import Path
import unittest

from package_identity_provisioner import ConflictError, GitHubReturnClient, Job, ProductConfig

CONFIG = ProductConfig.load(Path(__file__).resolve().parents[1] / "config.json")
SHA = "a" * 40


def job():
    return Job.validate({
        "schema_version": "1.0",
        "request_id": "3d-windows-preset-check-0001",
        "product_type": "GAME_3D",
        "source_factory": CONFIG.source_factory,
        "source_repository": CONFIG.source_repository,
        "source_branch": CONFIG.source_branch,
        "source_sha": SHA,
        "slug": "sample-product",
        "display_name": "Sample Product",
        "target_owner": CONFIG.target_owner,
        "dry_run": False,
        "requested_actions": ["BUILD_WINDOWS", "INSPECT_PACKAGE",
                              "LOOKUP_OFFICIAL_IDENTITY", "PROPOSE_GITHUB_RETURN"],
    }, CONFIG)


OFFICIAL = {
    "store_id": "9N1234567890",
    "name": "Sample.Product",
    "publisher": "CN=Test Publisher",
    "version": "1.2.3.4",
    "authenticated_account": "operator@example.invalid",
    "official_evidence_url": "https://partner.microsoft.com/dashboard/products/123",
}


class FakeAPI:
    def __init__(self, preset):
        self.preset = preset
        self.writes = 0

    def __call__(self, endpoint, body=None, allow_missing=False):
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": SHA}}
        if "/project.godot" in endpoint:
            return {"encoding": "base64",
                    "content": base64.b64encode(b'run/main_scene="res://scenes/main.tscn"').decode()}
        if "/export_presets.cfg" in endpoint:
            if self.preset is None:
                return None
            return {"encoding": "base64", "content": base64.b64encode(self.preset).decode()}
        if "/approved-identity.json" in endpoint:
            return None
        if endpoint == "graphql":
            self.writes += 1
            return {"data": {"createCommitOnBranch": {"commit": {
                "oid": "b" * 40, "url": "https://github.invalid/commit"}}}}
        raise AssertionError("Unexpected endpoint: " + endpoint)


class WindowsPresetReturnTests(unittest.TestCase):
    def assert_rejected(self, preset):
        api = FakeAPI(preset)
        with self.assertRaises(ConflictError):
            GitHubReturnClient(api).return_identity(job(), CONFIG, OFFICIAL, True)
        self.assertEqual(api.writes, 0)

    def test_missing_preset_blocks_identity_return(self):
        self.assert_rejected(None)

    def test_linux_only_preset_blocks_identity_return(self):
        self.assert_rejected(b'[preset.0]\nname="Linux"\nplatform="Linux"\n')

    def test_name_and_platform_in_different_sections_do_not_pass(self):
        self.assert_rejected(
            b'[preset.0]\nname="Windows Desktop"\nplatform="Linux"\n'
            b'[preset.1]\nname="Linux"\nplatform="Windows Desktop"\n')

    def test_non_utf8_preset_blocks_identity_return(self):
        self.assert_rejected(b"\xff\xfe")

    def test_valid_windows_preset_can_reach_atomic_commit(self):
        api = FakeAPI(b'[preset.0]\nname="Windows Desktop"\nplatform="Windows Desktop"\n')
        result = GitHubReturnClient(api).return_identity(job(), CONFIG, OFFICIAL, True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["commit_sha"], "b" * 40)
        self.assertEqual(api.writes, 1)


if __name__ == "__main__":
    unittest.main()
