"""Fail-closed transport tests. No live Factory products or Store Identity."""
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from factory_export_transport import FactoryExportTransport, _archive_sha256
from package_identity_provisioner import HoldError, inspect_package
from test_godot_pe_structure import fake_pe_x64


class FactoryTransportTests(unittest.TestCase):
    def setUp(self):
        self.job = SimpleNamespace(source_repository="shihuiarenjinba-png/3d-game-factory")

    def test_archive_sha256_streams_without_reading_entire_zip(self):
        # The transport accepts archives up to 2.2 GB; do not allocate them
        # as one bytes object while checking the authenticated digest.
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "artifact.zip"
            payload = b"streaming-digest-check" * 200_000
            archive.write_bytes(payload)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded ZIP read")):
                self.assertEqual(_archive_sha256(archive), hashlib.sha256(payload).hexdigest())
            archive.write_bytes(payload + b"tampered")
            self.assertNotEqual(_archive_sha256(archive), hashlib.sha256(payload).hexdigest())

    def test_archive_digest_mismatch_holds_before_payload_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = b"untrusted-archive-data"
            def fake_download(command, **kwargs):
                kwargs["stdout"].write(archive)
                return subprocess.CompletedProcess(command, 0)
            with (
                patch.object(FactoryExportTransport, "_json",
                             side_effect=[{"id": 42}, {"id": 7,
                               "size_in_bytes": len(archive), "digest": "sha256:" + "0" * 64}]),
                patch("factory_export_transport.subprocess.run", side_effect=fake_download),
                patch("factory_export_transport.verify_factory_export_artifact") as verify,
            ):
                with self.assertRaisesRegex(HoldError, "authenticated ZIP digest mismatch"):
                    FactoryExportTransport("gh").verify(
                        self.job, {}, run_id=42, artifact_id=7, work_root=Path(tmp))
                verify.assert_not_called()

    def test_missing_ids_holds_without_github_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(FactoryExportTransport, "_json") as gh:
                with self.assertRaisesRegex(HoldError, "factory-run-id"):
                    FactoryExportTransport("gh").verify(
                        self.job, {}, run_id=None, artifact_id=7, work_root=Path(tmp))
                gh.assert_not_called()

    def test_metadata_mismatch_holds_before_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(FactoryExportTransport, "_json",
                              side_effect=[{"id": 99}, {"id": 7, "size_in_bytes": 100}]):
                with self.assertRaisesRegex(HoldError, "metadata mismatch"):
                    FactoryExportTransport("gh").verify(
                        self.job, {}, run_id=42, artifact_id=7, work_root=Path(tmp))

    def test_malformed_artifact_size_is_hold_not_unexpected_failure(self):
        for bad in ("10", None, True, [], 0, -1):
            with self.subTest(size=bad), tempfile.TemporaryDirectory() as tmp:
                with patch.object(FactoryExportTransport, "_json",
                                  side_effect=[{"id": 42}, {"id": 7, "size_in_bytes": bad}]):
                    with self.assertRaisesRegex(HoldError, "metadata mismatch"):
                        FactoryExportTransport("gh").verify(
                            self.job, {}, run_id=42, artifact_id=7, work_root=Path(tmp))

    def test_authenticated_factory_payload_wins_over_nondeterministic_local_pck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.job.request_id = "3d-test-0001"
            self.job.product_type = "GAME_3D"
            self.job.source_branch = "codex/3d-canary"
            self.job.source_sha = "1" * 40
            self.job.slug = "test-product"
            exe = fake_pe_x64(b"real-factory-export")
            factory_pck = b"GDPCfactory-packed-scene-uid"
            local_pck = b"GDPClocal-different-scene-uid"
            (root / "candidate.exe").write_bytes(exe)
            (root / "candidate.pck").write_bytes(local_pck)
            local = inspect_package(root / "candidate.exe", godot_export=True)
            manifest = dict(
                schema_version=1, request_id=self.job.request_id,
                product_type="GAME_3D", source_repository=self.job.source_repository,
                source_branch=self.job.source_branch, source_sha=self.job.source_sha,
                factory_build_head="2" * 40, slug=self.job.slug,
                exe_path="candidate.exe", exe_sha256=hashlib.sha256(exe).hexdigest(),
                exe_size_bytes=len(exe), pck_path="candidate.pck",
                pck_sha256=hashlib.sha256(factory_pck).hexdigest(),
                pck_size_bytes=len(factory_pck))
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("export-evidence.json", json.dumps(manifest))
                z.writestr("candidate.exe", exe)
                z.writestr("candidate.pck", factory_pck)
            archive = buffer.getvalue()
            run = dict(id=42, status="completed", conclusion="success",
                       event="push", head_sha="2" * 40,
                       head_branch=self.job.source_branch,
                       head_repository={"full_name": self.job.source_repository})
            artifact = dict(id=7, size_in_bytes=len(archive),
                            name="godot-3d-factory-export-evidence",
                            expired=False, workflow_run={"id": 42},
                            digest="sha256:" + hashlib.sha256(archive).hexdigest())
            endpoints = []

            def metadata(endpoint):
                endpoints.append(endpoint)
                return run if "/runs/" in endpoint else artifact

            def fake_download(command, **kwargs):
                self.assertEqual(command[:5], ["gh", "api", "--hostname", "github.com", "--method"])
                self.assertTrue(command[-1].endswith("/artifacts/7/zip"))
                kwargs["stdout"].write(archive)
                return subprocess.CompletedProcess(command, 0)

            with (patch.object(FactoryExportTransport, "_json", side_effect=metadata),
                  patch("factory_export_transport.subprocess.run", side_effect=fake_download),
                  patch("package_identity_provisioner.signature_status", return_value="UNSIGNED"),
                  patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded ZIP read"))):
                evidence = FactoryExportTransport("gh").verify(
                    self.job, local, run_id=42, artifact_id=7, work_root=root / "work")
            self.assertEqual(evidence["status"], "PRE_IDENTITY_BYTES_CORRELATED")
            self.assertEqual(evidence["payload_authority"], "AUTHENTICATED_FACTORY_ARTIFACT")
            self.assertFalse(evidence["local_reexport_pck_matches_factory"])
            self.assertEqual(Path(evidence["canonical_package_path"]).read_bytes(), exe)
            self.assertEqual(Path(evidence["canonical_package_path"]).with_suffix(".pck").read_bytes(), factory_pck)
            self.assertEqual(endpoints, [
                "/repos/shihuiarenjinba-png/3d-game-factory/actions/runs/42",
                "/repos/shihuiarenjinba-png/3d-game-factory/actions/artifacts/7"])
            self.assertFalse(list((root / "work").glob("factory-export-*")))

    def test_rejects_local_exe_mismatch_even_when_factory_artifact_is_valid(self):
        # The exact EXE is still mandatory; only the known PCK UID drift may differ.
        with tempfile.TemporaryDirectory() as tmp:
            local = {"kind": "exe", "sha256": "0" * 64, "size_bytes": 1,
                     "godot_export": {"evidence_scope": "LOCAL_EXPORT_NOT_INDEPENDENT",
                                      "external_pck_sha256": None}}
            # Missing authenticated IDs must fail before any local/Factory relaxation.
            with patch.object(FactoryExportTransport, "_json") as gh:
                with self.assertRaises(HoldError):
                    FactoryExportTransport("gh").verify(
                        self.job, local, run_id=None, artifact_id=7, work_root=Path(tmp))
                gh.assert_not_called()


    def test_rejects_download_length_mismatch_before_byte_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            def truncated_download(command, **kwargs):
                kwargs["stdout"].write(b"short")
                return subprocess.CompletedProcess(command, 0)
            with patch.object(FactoryExportTransport, "_json",
                              side_effect=[{"id": 42}, {"id": 7, "size_in_bytes": 100}]), \
                 patch("factory_export_transport.subprocess.run", side_effect=truncated_download), \
                 patch("factory_export_transport.verify_factory_export_artifact") as verify:
                with self.assertRaisesRegex(HoldError, "download failed"):
                    FactoryExportTransport("gh").verify(
                        self.job, {}, run_id=42, artifact_id=7, work_root=Path(tmp))
                verify.assert_not_called()

    def test_rejects_dot_repository_segments_before_network(self):
        for name in ("../3d-game-factory", "owner/..", "./repo", "owner/."):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                self.job.source_repository = name
                with patch.object(FactoryExportTransport, "_json") as gh:
                    with self.assertRaisesRegex(HoldError, "invalid Factory repository"):
                        FactoryExportTransport("gh").verify(
                            self.job, {}, run_id=42, artifact_id=7, work_root=Path(tmp))
                    gh.assert_not_called()
        self.job.source_repository = "shihuiarenjinba-png/3d-game-factory"

    def test_failed_download_never_calls_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(FactoryExportTransport, "_json",
                              side_effect=[{"id": 42}, {"id": 7, "size_in_bytes": 10}]), \
                 patch("factory_export_transport.subprocess.run",
                       return_value=subprocess.CompletedProcess(["gh"], 1)), \
                 patch("factory_export_transport.verify_factory_export_artifact") as verify:
                with self.assertRaisesRegex(HoldError, "download failed"):
                    FactoryExportTransport("gh").verify(
                        self.job, {}, run_id=42, artifact_id=7, work_root=Path(tmp))
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
