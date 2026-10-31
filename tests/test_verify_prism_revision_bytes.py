"""Synthetic ZIP and tamper regressions; actual GitHub downloads run in CI."""
import copy
from datetime import datetime, timedelta
import hashlib
from io import BytesIO
import json
from pathlib import Path
import unittest
import zipfile

from prism_revision_handoff_contract import RevisionHandoffError
from verify_prism_revision_bytes import (
    verify_payload_bytes, _safe_zip, FACTORY_REPO, PROVISIONER_REPO,
)

HANDOFF = Path(__file__).resolve().parents[1] / "handoffs/prism-route-3d-sentinel-revision-20261029.json"


def pack(entries):
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return output.getvalue()


class PrismRevisionByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads(HANDOFF.read_text(encoding="utf-8"))
        cls.now = datetime.fromisoformat(
            cls.original["evidence_observed_at"].replace("Z", "+00:00")
        ) + timedelta(seconds=1)

    def fixture(self):
        h = copy.deepcopy(self.original)
        exe, pck = b"MZ" + b"E" * 2048, b"GDPC" + b"P" * 1024
        sha = lambda data: hashlib.sha256(data).hexdigest()
        record = {
            "source_sha": h["source_sha"],
            "factory_build_head": h["source_sha"],
            "source_branch": h["source_branch"],
            "source_repository": FACTORY_REPO,
            "request_id": h["request_id"],
            "slug": h["slug"],
            "exe_path": "candidate.exe",
            "pck_path": "candidate.pck",
            "exe_sha256": sha(exe),
            "exe_size_bytes": len(exe),
            "pck_sha256": sha(pck),
            "pck_size_bytes": len(pck),
        }
        factory = pack({
            "candidate.exe": exe, "candidate.pck": pck,
            "export-evidence.json": json.dumps(record).encode(),
        })
        msix = pack({
            "Game/game.exe": exe, "Game/game.pck": pck,
            "AppxManifest.xml": b"""<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
 <Identity Name="Example.ThreeD.Fixture" Publisher="CN=Offline QA Fixture"
  Version="1.0.0.0" ProcessorArchitecture="x64"/>
 <Applications><Application Id="Game" Executable="Game\\game.exe"
  EntryPoint="Windows.FullTrustApplication"/></Applications>
 <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>""",
        })
        report = {
            "source_sha": h["source_sha"],
            "request_id": h["request_id"],
            "factory_run_id": h["evidence"]["factory"]["run_id"],
            "factory_artifact_id": h["evidence"]["factory"]["artifact_id"],
            "factory_artifact_sha256": sha(factory),
            "exe_sha256": sha(exe), "pck_sha256": sha(pck),
            "msix_sha256": sha(msix), "msix_bytes": len(msix),
            "signature_verified": False,
            "store_submission_allowed": False,
            "package_version_gate": "HOLD",
            "identity_rebinding_status": "HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING",
        }
        qa = pack({
            "prism-route-3d-sentinel-qa-unsigned.msix": msix,
            "makeappx-evidence.json": json.dumps(report).encode(),
        })
        for key, raw in (("factory", factory), ("unsigned_makeappx", qa)):
            h["evidence"][key]["archive_bytes"] = len(raw)
            h["evidence"][key]["archive_digest"] = "sha256:" + sha(raw)
        blobs = {
            (FACTORY_REPO, h["evidence"]["factory"]["artifact_id"]): factory,
            (PROVISIONER_REPO, h["evidence"]["unsigned_makeappx"]["artifact_id"]): qa,
        }
        return h, blobs

    def verify(self, h, blobs):
        return verify_payload_bytes(
            h, lambda repo, artifact: blobs[(repo, artifact)], now=self.now)

    def test_real_byte_correlation_is_hold_only(self):
        h, blobs = self.fixture()
        result = self.verify(h, blobs)
        self.assertTrue(result["artifact_zip_bytes_verified"])
        self.assertTrue(result["inner_exe_pck_msix_verified"])
        self.assertTrue(result["unsigned_qa_fixture_identity_detected"])
        self.assertFalse(result["product_identity_verified"])
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["store_submission_allowed"])
        self.assertFalse(result["signature_verified"])

    def test_zip_byte_tamper_rejected(self):
        h, blobs = self.fixture()
        key = (FACTORY_REPO, h["evidence"]["factory"]["artifact_id"])
        blobs[key] += b"x"
        with self.assertRaisesRegex(RevisionHandoffError, "ZIP byte mismatch"):
            self.verify(h, blobs)

    def test_nested_payload_tamper_rejected_even_if_outer_hashes_updated(self):
        h, blobs = self.fixture()
        key = (PROVISIONER_REPO, h["evidence"]["unsigned_makeappx"]["artifact_id"])
        with zipfile.ZipFile(BytesIO(blobs[key])) as archive:
            entries = {n: archive.read(n) for n in archive.namelist()}
        msix_name = "prism-route-3d-sentinel-qa-unsigned.msix"
        with zipfile.ZipFile(BytesIO(entries[msix_name])) as archive:
            nested = {n: archive.read(n) for n in archive.namelist()}
        nested["Game/game.pck"] += b"tamper"
        entries[msix_name] = pack(nested)
        report = json.loads(entries["makeappx-evidence.json"])
        report["msix_bytes"] = len(entries[msix_name])
        report["msix_sha256"] = hashlib.sha256(entries[msix_name]).hexdigest()
        entries["makeappx-evidence.json"] = json.dumps(report).encode()
        blobs[key] = pack(entries)
        h["evidence"]["unsigned_makeappx"]["archive_bytes"] = len(blobs[key])
        h["evidence"]["unsigned_makeappx"]["archive_digest"] = (
            "sha256:" + hashlib.sha256(blobs[key]).hexdigest())
        with self.assertRaisesRegex(RevisionHandoffError, "length mismatch"):
            self.verify(h, blobs)

    def test_changed_unsigned_manifest_identity_rejected_with_consistent_hashes(self):
        h, blobs = self.fixture()
        key = (PROVISIONER_REPO, h["evidence"]["unsigned_makeappx"]["artifact_id"])
        with zipfile.ZipFile(BytesIO(blobs[key])) as archive:
            entries = {n: archive.read(n) for n in archive.namelist()}
        msix_name = "prism-route-3d-sentinel-qa-unsigned.msix"
        with zipfile.ZipFile(BytesIO(entries[msix_name])) as archive:
            nested = {n: archive.read(n) for n in archive.namelist()}
        nested["AppxManifest.xml"] = nested["AppxManifest.xml"].replace(
            b"Example.ThreeD.Fixture", b"Prism.Route.3D")
        entries[msix_name] = pack(nested)
        report = json.loads(entries["makeappx-evidence.json"])
        report["msix_bytes"] = len(entries[msix_name])
        report["msix_sha256"] = hashlib.sha256(entries[msix_name]).hexdigest()
        entries["makeappx-evidence.json"] = json.dumps(report).encode()
        blobs[key] = pack(entries)
        h["evidence"]["unsigned_makeappx"]["archive_bytes"] = len(blobs[key])
        h["evidence"]["unsigned_makeappx"]["archive_digest"] = (
            "sha256:" + hashlib.sha256(blobs[key]).hexdigest())
        with self.assertRaisesRegex(RevisionHandoffError, "fixture manifest mismatch"):
            self.verify(h, blobs)

    def _rewrite_qa_msix_with_consistent_outer_hashes(self, h, blobs, mutate):
        """Attack the nested MSIX while keeping report and archive digests valid."""
        key = (PROVISIONER_REPO, h["evidence"]["unsigned_makeappx"]["artifact_id"])
        with zipfile.ZipFile(BytesIO(blobs[key])) as outer:
            entries = {name: outer.read(name) for name in outer.namelist()}
        name = "prism-route-3d-sentinel-qa-unsigned.msix"
        with zipfile.ZipFile(BytesIO(entries[name])) as inner:
            nested = {entry: inner.read(entry) for entry in inner.namelist()}
        mutate(nested)
        entries[name] = pack(nested)
        report = json.loads(entries["makeappx-evidence.json"])
        report["msix_bytes"] = len(entries[name])
        report["msix_sha256"] = hashlib.sha256(entries[name]).hexdigest()
        entries["makeappx-evidence.json"] = json.dumps(report).encode()
        blobs[key] = pack(entries)
        h["evidence"]["unsigned_makeappx"]["archive_bytes"] = len(blobs[key])
        h["evidence"]["unsigned_makeappx"]["archive_digest"] = (
            "sha256:" + hashlib.sha256(blobs[key]).hexdigest())

    def test_signature_bearing_qa_msix_rejected_despite_consistent_hashes(self):
        h, blobs = self.fixture()
        self._rewrite_qa_msix_with_consistent_outer_hashes(
            h, blobs, lambda entries: entries.update({"AppxSignature.p7x": b"forged"}))
        with self.assertRaisesRegex(RevisionHandoffError, "signed package cannot pass unsigned QA"):
            self.verify(h, blobs)

    def test_fixture_version_drift_rejected_despite_consistent_hashes(self):
        h, blobs = self.fixture()
        def alter(entries):
            original = entries["AppxManifest.xml"]
            self.assertIn(b'Version="1.0.0.0"', original)
            entries["AppxManifest.xml"] = original.replace(
                b'Version="1.0.0.0"', b'Version="9.9.9.0"')
        self._rewrite_qa_msix_with_consistent_outer_hashes(h, blobs, alter)
        with self.assertRaisesRegex(RevisionHandoffError, "fixture manifest mismatch"):
            self.verify(h, blobs)

    def test_case_insensitive_windows_path_collision_rejected(self):
        with self.assertRaisesRegex(RevisionHandoffError, "case-insensitive ZIP path collision"):
            with _safe_zip(pack({"Game/game.exe": b"MZ", "game/GAME.exe": b"MZ"})):
                pass

    def test_windows_invalid_zip_paths_rejected(self):
        for name in ("Game/CON.txt", "Game/trailing. ", "Game/AUX",
                     "Game/bad?.txt", "Game/bad\\x1fname"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(RevisionHandoffError, "unsafe Windows ZIP path"):
                    with _safe_zip(pack({name: b"invalid"})):
                        pass

    def test_zip_path_traversal_rejected(self):
        h, blobs = self.fixture()
        key = (FACTORY_REPO, h["evidence"]["factory"]["artifact_id"])
        with zipfile.ZipFile(BytesIO(blobs[key])) as archive:
            entries = {n: archive.read(n) for n in archive.namelist()}
        entries["../escape"] = b"bad"
        blobs[key] = pack(entries)
        h["evidence"]["factory"]["archive_bytes"] = len(blobs[key])
        h["evidence"]["factory"]["archive_digest"] = (
            "sha256:" + hashlib.sha256(blobs[key]).hexdigest())
        with self.assertRaisesRegex(RevisionHandoffError, "unsafe ZIP entry"):
            self.verify(h, blobs)


if __name__ == "__main__":
    unittest.main()
