"""Offline adversarial tests for Factory export byte/provenance correlation.

These fixtures are not runnable games, Microsoft Identity, or product MSIX.
"""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import zipfile

from factory_export_evidence import verify_factory_export_artifact
from package_identity_provisioner import HoldError, inspect_package
from test_godot_pe_structure import fake_pe_x64

SOURCE = "1" * 40
BUILD = "2" * 40
EXE = fake_pe_x64(b"factory-export-bytes")
PCK = b"GDPC" + b"factory-pck-data"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FactoryExportEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.exe = self.root / "candidate.exe"
        self.exe.write_bytes(EXE)
        (self.root / "candidate.pck").write_bytes(PCK)
        self.local = inspect_package(self.exe, godot_export=True)
        self.job = SimpleNamespace(request_id="3d-test-0001", product_type="GAME_3D",
                                   source_repository="shihuiarenjinba-png/3d-game-factory",
                                   source_branch="codex/3d-test", source_sha=SOURCE,
                                   slug="test-product")
        self.manifest = {
            "schema_version": 1, "request_id": self.job.request_id,
            "product_type": "GAME_3D", "source_repository": self.job.source_repository,
            "source_branch": self.job.source_branch, "source_sha": SOURCE,
            "factory_build_head": BUILD, "slug": self.job.slug,
            "exe_path": "candidate.exe", "exe_sha256": sha(EXE),
            "exe_size_bytes": len(EXE), "pck_path": "candidate.pck",
            "pck_sha256": sha(PCK), "pck_size_bytes": len(PCK),
        }
        self.run = {
            "id": 1234, "status": "completed", "conclusion": "success",
            "event": "workflow_dispatch", "head_sha": BUILD,
            "head_branch": self.job.source_branch,
            "head_repository": {"full_name": self.job.source_repository},
        }
        self.artifact = {
            "id": 5678, "name": "godot-3d-factory-export-evidence",
            "expired": False, "workflow_run": {"id": 1234},
        }
        self.archive = self.root / "factory-artifact.zip"
        self.make_archive()

    def make_archive(self, exe=EXE, pck=PCK, extra=None):
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("export-evidence.json", json.dumps(self.manifest))
            z.writestr("candidate.exe", exe)
            if pck is not None:
                z.writestr("candidate.pck", pck)
            if extra is not None:
                z.writestr(extra, b"bad")
        self.artifact["digest"] = "sha256:" + sha(self.archive.read_bytes())

    def verify(self):
        return verify_factory_export_artifact(
            self.job, self.local, self.archive, self.run, self.artifact)

    def test_valid_separate_pck_correlation_preserves_source_and_build_sha(self):
        result = self.verify()
        self.assertEqual(result["status"], "PRE_IDENTITY_BYTES_CORRELATED")
        self.assertEqual(result["source_sha"], SOURCE)
        self.assertEqual(result["factory_build_head"], BUILD)
        self.assertFalse(result["post_identity_ready"])
        self.assertFalse(result["windows_install_gpu_gui_verified"])

    def test_reject_changed_request_source_slug(self):
        for key, value in [("request_id", "other-request"), ("source_sha", BUILD),
                           ("slug", "another-game"), ("source_branch", "codex/other")]:
            with self.subTest(key=key):
                old = self.manifest[key]
                self.manifest[key] = value
                self.make_archive()
                with self.assertRaises(HoldError):
                    self.verify()
                self.manifest[key] = old

    def test_reject_local_exe_or_pck_mismatch(self):
        for key, value in [("sha256", "f" * 64), ("size_bytes", 9999)]:
            with self.subTest(key=key):
                old = self.local[key]
                self.local[key] = value
                with self.assertRaises(HoldError):
                    self.verify()
                self.local[key] = old
        self.local["godot_export"]["external_pck_sha256"] = "e" * 64
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_repacked_pck_even_when_zip_digest_is_updated(self):
        self.make_archive(pck=b"GDPCtampered")
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_modified_exe_even_when_zip_digest_is_updated(self):
        self.make_archive(exe=EXE + b"tampered")
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_wrong_factory_build_head_or_run(self):
        self.run["head_sha"] = SOURCE
        with self.assertRaises(HoldError):
            self.verify()
        self.run["head_sha"] = BUILD
        self.artifact["workflow_run"]["id"] = 999
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_expired_failed_or_fixture_artifact(self):
        self.artifact["expired"] = True
        with self.assertRaises(HoldError):
            self.verify()
        self.artifact["expired"] = False
        self.run["conclusion"] = "failure"
        with self.assertRaises(HoldError):
            self.verify()
        self.run["conclusion"] = "success"
        self.artifact["name"] = "godot-4-3-real-export-makeappx-fixture-not-product"
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_zip_digest_mismatch(self):
        self.artifact["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_extra_zip_member(self):
        self.make_archive(extra="../evil")
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_duplicate_zip_member(self):
        with zipfile.ZipFile(self.archive, "a") as z:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                z.writestr("candidate.exe", EXE)
        self.artifact["digest"] = "sha256:" + sha(self.archive.read_bytes())
        with self.assertRaises(HoldError):
            self.verify()

    def test_reject_pck_presence_mismatch(self):
        self.make_archive(pck=None)
        with self.assertRaises(HoldError):
            self.verify()

    def test_embedded_pck_contract_without_external_pck(self):
        self.manifest.update(pck_path=None, pck_sha256=None, pck_size_bytes=None)
        self.local["godot_export"].update(external_pck_sha256=None,
                                           external_pck_size_bytes=None)
        self.make_archive(pck=None)
        result = self.verify()
        self.assertIsNone(result["external_pck_sha256"])


if __name__ == "__main__":
    unittest.main()
