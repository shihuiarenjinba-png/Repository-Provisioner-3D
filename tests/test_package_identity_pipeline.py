import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from package_identity_provisioner import (
    ConflictError, GitHubReturnClient, HoldError, Job, Ledger, OfficialIdentityProvider,
    PackageBuilder, ProductConfig, Provisioner, RequestLock, RetryableError,
    SourceManager, compare_package_identity, inspect_package, redact,
    windows_all_auto_record, _package_family_name,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
TEST_TEMP = ROOT / ".test-tmp"
TEST_TEMP.mkdir(exist_ok=True)
tempfile.tempdir = str(TEST_TEMP)


def config():
    return ProductConfig.load(ROOT / "config.json")


def job(**updates):
    cfg = config()
    value = {
        "schema_version": "1.0", "request_id": "req-0001", "product_type": cfg.product_type,
        "source_factory": cfg.source_factory, "source_repository": cfg.source_repository,
        "source_branch": cfg.source_branch, "source_sha": SHA, "slug": "sample-product",
        "display_name": "Sample Product", "target_owner": cfg.target_owner, "dry_run": False,
        "requested_actions": ["BUILD_WINDOWS", "INSPECT_PACKAGE", "LOOKUP_OFFICIAL_IDENTITY", "PROPOSE_GITHUB_RETURN"],
    }
    value.update(updates)
    return value


def evidence(**updates):
    cfg = config()
    value = {
        "request_id": "req-0001", "product_type": cfg.product_type, "slug": "sample-product",
        "source_sha": SHA, "authenticated_account": "partner-operator@example.invalid",
        "verified_at": "2026-10-26T00:00:00Z",
        "official_evidence_url": "https://partner.microsoft.com/dashboard/products/123",
        "store_id": "9N1234567890", "name": "Sample.Product", "publisher": "CN=Test Publisher",
        "version": "1.2.3.4",
    }
    value.update(updates)
    return value


def make_msix(path: Path, name="Sample.Product", publisher="CN=Test Publisher", version="1.2.3.4"):
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
    <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
      <Identity Name="{name}" Publisher="{publisher}" Version="{version}" />
    </Package>'''
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AppxManifest.xml", manifest)
        archive.writestr("payload.txt", "payload")
    return path


class FakeSource:
    def __init__(self):
        self.calls = 0
    def acquire(self, _job, destination):
        self.calls += 1
        destination.mkdir(parents=True, exist_ok=True)
        return destination


class FakeBuilder:
    def __init__(self, artifact_kind="msix", name="Sample.Product"):
        self.calls, self.artifact_kind, self.name = 0, artifact_kind, name
    def build(self, _job, _source, output_dir, _config):
        self.calls += 1
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / ("candidate.msix" if self.artifact_kind == "msix" else "candidate.exe")
        if self.artifact_kind == "msix":
            return make_msix(path, name=self.name)
        path.write_bytes(b"MZ-not-a-real-binary")
        return path


class FakeIdentity:
    def __init__(self, value=None, error=None):
        self.value, self.error, self.calls = value or evidence(), error, 0
    def lookup(self, _job):
        self.calls += 1
        if self.error:
            raise self.error
        return dict(self.value)


class FakeGitHub:
    def __init__(self, result=None, error=None):
        self.result = result or {"status": "APPLIED", "repository": config().source_repository,
                                 "branch": config().source_branch, "path": "products/sample-product/store/approved-identity.json",
                                 "commit_sha": "b" * 40, "commit_url": "https://github.com/example/commit"}
        self.error, self.calls = error, 0
    def return_identity(self, *_args, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        if not kwargs.get("apply", False):
            return {**self.result, "status": "NOT_APPLIED", "commit_sha": None, "commit_url": None}
        return dict(self.result)


class ContractValidationTests(unittest.TestCase):
    def test_valid_job(self):
        self.assertEqual(Job.validate(job(), config()).source_sha, SHA)
    def test_wrong_product_type_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(product_type="WRONG"), config())
    def test_wrong_factory_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(source_factory="other"), config())
    def test_wrong_repository_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(source_repository="owner/other"), config())
    def test_wrong_return_branch_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(source_branch="main"), config())
    def test_placeholder_sha_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(source_sha="0" * 40), config())
    def test_unknown_input_field_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(command="arbitrary"), config())
    def test_unknown_action_is_hold(self):
        with self.assertRaises(HoldError):
            Job.validate(job(requested_actions=["DELETE_REPOSITORY"]), config())


class PackageInspectionTests(unittest.TestCase):
    def test_msix_identity_hash_and_family_are_collected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = inspect_package(make_msix(Path(tmp) / "candidate.msix"))
        self.assertEqual(result["package_identity"], "Sample.Product")
        self.assertEqual(result["publisher"], "CN=Test Publisher")
        self.assertEqual(result["version"], "1.2.3.4")
        self.assertRegex(result["sha256"], r"^[0-9a-f]{64}$")
        if os.name == "nt":
            self.assertTrue(result["package_family_name"].startswith("Sample.Product_"))
        else:
            self.assertIsNone(result["package_family_name"])
    @unittest.skipUnless(os.name == "nt", "Windows AppModel API required")
    def test_publisher_id_uses_windows_appmodel_api(self):
        publisher = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        self.assertEqual(_package_family_name("Microsoft.Windows.Photos", publisher),
                         "Microsoft.Windows.Photos_8wekyb3d8bbwe")
    def test_exe_has_hash_but_no_package_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.exe"
            path.write_bytes(b"MZ")
            result = inspect_package(path)
        self.assertIsNone(result["package_identity"])
        self.assertEqual(result["kind"], "exe")
    def test_invalid_msix_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.msix"
            path.write_bytes(b"not zip")
            with self.assertRaises(HoldError):
                inspect_package(path)


class IdentityEvidenceTests(unittest.TestCase):
    def test_matching_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity.json"
            path.write_text(json.dumps(evidence()), encoding="utf-8")
            result = OfficialIdentityProvider(path).lookup(Job.validate(job(), config()))
        self.assertEqual(result["store_id"], "9N1234567890")
    def test_untrusted_evidence_url_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity.json"
            path.write_text(json.dumps(evidence(official_evidence_url="https://evil.invalid/x")), encoding="utf-8")
            with self.assertRaises(HoldError):
                OfficialIdentityProvider(path).lookup(Job.validate(job(), config()))
    def test_evidence_for_other_sha_is_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity.json"
            path.write_text(json.dumps(evidence(source_sha="b" * 40)), encoding="utf-8")
            with self.assertRaises(ConflictError):
                OfficialIdentityProvider(path).lookup(Job.validate(job(), config()))
    def test_package_identity_mismatch_is_conflict(self):
        with self.assertRaises(ConflictError):
            compare_package_identity({"kind": "msix", "package_identity": "Other", "publisher": "CN=Test Publisher", "version": "1.2.3.4"}, evidence())
    def test_exe_cannot_approve_official_identity(self):
        with self.assertRaises(HoldError):
            compare_package_identity({"kind": "exe"}, evidence())
    def test_windows_all_auto_adapter(self):
        contract = windows_all_auto_record(Job.validate(job(), config()), evidence())
        self.assertEqual(contract["expected_head_sha"], SHA)
        self.assertTrue(contract["operator_verified"])


class GitHubReturnTests(unittest.TestCase):
    def api(self, endpoint, body=None, allow_missing=False):
        if "git/ref/heads/" in endpoint:
            return {"object": {"sha": SHA}}
        if "/manifest.json" in endpoint:
            raw = json.dumps({"slug": "sample-product", "kind": "app" if config().product_type == "APP" else "game"}).encode()
            return {"encoding": "base64", "content": base64.b64encode(raw).decode()}
        if "/project.godot" in endpoint:
            return {"encoding": "base64", "content": base64.b64encode(b"run/main_scene=x").decode()}
        if "/approved-identity.json" in endpoint:
            return None
        if endpoint == "graphql":
            return {"data": {"createCommitOnBranch": {"commit": {"oid": "b" * 40, "url": "https://github.invalid/c"}}}}
        raise AssertionError(endpoint)

    def test_atomic_apply_returns_real_commit_sha(self):
        result = GitHubReturnClient(self.api).return_identity(Job.validate(job(), config()), config(), evidence(), True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["commit_sha"], "b" * 40)
    def test_no_apply_is_side_effect_free(self):
        def forbidden(*_a, **_k):
            raise AssertionError("API must not be called")
        result = GitHubReturnClient(forbidden).return_identity(Job.validate(job(), config()), config(), evidence(), False)
        self.assertEqual(result["status"], "NOT_APPLIED")
    def test_head_mismatch_is_conflict(self):
        def wrong_head(*_a, **_k):
            return {"object": {"sha": "c" * 40}}
        with self.assertRaises(ConflictError):
            GitHubReturnClient(wrong_head).return_identity(Job.validate(job(), config()), config(), evidence(), True)
    def test_existing_different_identity_is_conflict(self):
        def existing(endpoint, body=None, allow_missing=False):
            if "git/ref" in endpoint:
                return {"object": {"sha": SHA}}
            if "/manifest.json" in endpoint:
                raw = json.dumps({"slug": "sample-product", "kind": "app" if config().product_type == "APP" else "game"}).encode()
                return {"encoding": "base64", "content": base64.b64encode(raw).decode()}
            return {"encoding": "base64", "content": base64.b64encode(b'{"store_id":"OTHER000"}').decode()}
        with self.assertRaises(ConflictError):
            GitHubReturnClient(existing).return_identity(Job.validate(job(), config()), config(), evidence(), True)


class OrchestratorTests(unittest.TestCase):
    def runner(self, root, source=None, builder=None, identity=None, github=None):
        return Provisioner(config(), Path(root) / "state", Path(root) / "work",
                           source=source or FakeSource(), builder=builder or FakeBuilder(),
                           identity=identity or FakeIdentity(), github=github or FakeGitHub())

    def test_dry_run_has_no_external_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, builder, identity, github = FakeSource(), FakeBuilder(), FakeIdentity(), FakeGitHub()
            result = self.runner(tmp, source, builder, identity, github).run(job(dry_run=True), apply=True)
        self.assertEqual(result["status"], "DRY_RUN")
        self.assertEqual((source.calls, builder.calls, identity.calls, github.calls), (0, 0, 0, 0))
    def test_successful_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(tmp).run(job(), apply=True)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["github_return"]["commit_sha"], "b" * 40)
    def test_without_apply_holds_after_local_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(tmp).run(job(), apply=False)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["next_stage"], "APPLY_VERIFIED_GITHUB_RETURN")
    def test_duplicate_request_replays_without_rebuilding(self):
        with tempfile.TemporaryDirectory() as tmp:
            builder = FakeBuilder()
            runner = self.runner(tmp, builder=builder)
            first = runner.run(job(), apply=True)
            second = runner.run(job(), apply=True)
        self.assertEqual(first["status"], "COMPLETED")
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(builder.calls, 1)
    def test_dry_run_can_promote_to_live_after_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, builder, identity, github = FakeSource(), FakeBuilder(), FakeIdentity(), FakeGitHub()
            runner = self.runner(tmp, source, builder, identity, github)
            preview = runner.run(job(dry_run=True), apply=False)
            self.assertEqual(preview["status"], "DRY_RUN")
            self.assertEqual((source.calls, builder.calls, identity.calls, github.calls), (0, 0, 0, 0))
            live = runner.run(job(dry_run=False), apply=True)
            replay = runner.run(job(dry_run=False), apply=True)
            self.assertEqual(live["status"], "COMPLETED")
            self.assertFalse(live["idempotent_replay"])
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual((source.calls, builder.calls, identity.calls, github.calls), (1, 1, 1, 1))

    def test_conflicting_promotion_cannot_replace_original_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            builder = FakeBuilder()
            runner = self.runner(tmp, builder=builder)
            preview = runner.run(job(dry_run=True), apply=False)
            wrong = runner.run(job(dry_run=False, source_sha="b" * 40), apply=True)
            stored = runner.ledger.read("req-0001")
            correct = runner.run(job(dry_run=False), apply=True)
            self.assertEqual(preview["status"], "DRY_RUN")
            self.assertEqual(wrong["status"], "CONFLICT")
            self.assertEqual(stored["response"]["status"], "DRY_RUN")
            self.assertEqual(correct["status"], "COMPLETED")
            self.assertEqual(builder.calls, 1)

    def test_same_request_different_sha_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp)
            runner.run(job(dry_run=True), apply=False)
            result = runner.run(job(dry_run=True, source_sha="b" * 40), apply=False)
        self.assertEqual(result["status"], "CONFLICT")
    def test_missing_identity_is_hold_and_can_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp, identity=FakeIdentity(error=HoldError("identity missing")))
            first = runner.run(job(), apply=True)
            runner.identity = FakeIdentity()
            second = runner.run(job(), apply=True)
        self.assertEqual(first["status"], "HOLD")
        self.assertEqual(second["status"], "COMPLETED")
    def test_retryable_github_failure_is_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(tmp, github=FakeGitHub(error=RetryableError("rate limit"))).run(job(), apply=True)
        self.assertEqual(result["status"], "RETRYABLE_FAILURE")
    def test_package_mismatch_is_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(tmp, builder=FakeBuilder(name="Other.Product")).run(job(), apply=True)
        self.assertEqual(result["status"], "CONFLICT")
    def test_exe_only_build_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(tmp, builder=FakeBuilder(artifact_kind="exe")).run(job(), apply=True)
        self.assertEqual(result["status"], "HOLD")
    def test_type_state_is_namespaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp)
            runner.run(job(dry_run=True), apply=False)
            self.assertIn(config().product_type.lower(), str(runner.ledger.records))


class FailureClassificationTests(unittest.TestCase):
    def test_git_timeout_is_retryable(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["git"], 1)):
            with self.assertRaises(RetryableError):
                SourceManager._run(["git", "fetch"], 1)
    def test_github_timeout_is_retryable(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["gh"], 1)):
            with self.assertRaises(RetryableError):
                GitHubReturnClient._gh_api("graphql")
    def test_github_401_is_hold(self):
        completed = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 401: Bad credentials")
        with patch("subprocess.run", return_value=completed), self.assertRaises(HoldError):
            GitHubReturnClient._gh_api("graphql")
    def test_github_403_is_hold(self):
        completed = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 403: Resource not accessible")
        with patch("subprocess.run", return_value=completed), self.assertRaises(HoldError):
            GitHubReturnClient._gh_api("graphql")
    def test_github_404_is_conflict(self):
        completed = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 404: Not Found")
        with patch("subprocess.run", return_value=completed), self.assertRaises(ConflictError):
            GitHubReturnClient._gh_api("graphql")
    def test_github_422_is_conflict(self):
        completed = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 422: Validation Failed")
        with patch("subprocess.run", return_value=completed), self.assertRaises(ConflictError):
            GitHubReturnClient._gh_api("graphql")
    def test_github_429_is_retryable(self):
        completed = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 429: rate limit")
        with patch("subprocess.run", return_value=completed), self.assertRaises(RetryableError):
            GitHubReturnClient._gh_api("graphql")
    def test_secret_redaction(self):
        self.assertNotIn("supersecret", redact("Authorization: bearer supersecret"))
    def test_live_builder_rejects_unknown_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(HoldError):
                PackageBuilder()._build_windows(Path(tmp))
    def test_godot_missing_project_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(HoldError):
                PackageBuilder()._build_godot(root, root / "out")
    def test_godot_invalid_project_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "project.godot").write_text("[application]", encoding="utf-8")
            (root / "export_presets.cfg").write_text("[preset.0]", encoding="utf-8")
            with self.assertRaises(HoldError):
                PackageBuilder()._build_godot(root, root / "out")
    def test_parallel_lock_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "same.lock"
            with RequestLock(path):
                with self.assertRaises(ConflictError):
                    RequestLock(path).__enter__()
    def test_ledger_is_atomic_and_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp))
            ledger.write("req", {"value": 1})
            self.assertEqual(ledger.read("req"), {"value": 1})


if __name__ == "__main__":
    unittest.main()
