"""Fail-closed transport tests. No live Factory products or Store Identity."""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from factory_export_transport import FactoryExportTransport
from package_identity_provisioner import HoldError


class FactoryTransportTests(unittest.TestCase):
    def setUp(self):
        self.job = SimpleNamespace(source_repository="shihuiarenjinba-png/3d-game-factory")

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

    def test_success_uses_authenticated_independent_metadata_and_exact_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = {"id": 42}
            artifact = {"id": 7, "size_in_bytes": len(b"ZIP-BYTES")}
            endpoints = []
            def metadata(endpoint):
                endpoints.append(endpoint)
                return run if "/runs/" in endpoint else artifact
            def fake_download(command, **kwargs):
                self.assertEqual(command[:5], ["gh", "api", "--hostname", "github.com", "--method"])
                self.assertTrue(command[-1].endswith("/artifacts/7/zip"))
                kwargs["stdout"].write(b"ZIP-BYTES")
                return subprocess.CompletedProcess(command, 0)
            with patch.object(FactoryExportTransport, "_json", side_effect=metadata), \
                 patch("factory_export_transport.subprocess.run", side_effect=fake_download), \
                 patch("factory_export_transport.verify_factory_export_artifact",
                       return_value={"status": "PRE_IDENTITY_BYTES_CORRELATED"}) as verify:
                result = FactoryExportTransport("gh").verify(
                    self.job, {"kind": "exe"}, run_id=42, artifact_id=7, work_root=Path(tmp))
            self.assertEqual(result["status"], "PRE_IDENTITY_BYTES_CORRELATED")
            self.assertEqual(endpoints, [
                "/repos/shihuiarenjinba-png/3d-game-factory/actions/runs/42",
                "/repos/shihuiarenjinba-png/3d-game-factory/actions/artifacts/7"])
            self.assertEqual(verify.call_args.args[3:], (run, artifact))
            self.assertFalse(list(Path(tmp).glob("factory-export-*")))


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
