"""Fail-closed tests for current-source Prism Route 3D MSIX packaging."""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

import prism_current_source_msix_builder as builder


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def png_bytes(width: int, height: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    row = b"\x00" + (b"\x10\x20\x30\xff" * width)
    raw = row * height
    return (
        builder.PNG_SIGNATURE
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


class CurrentSourceMsixBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "candidate.exe"
        self.pck = self.root / "candidate.pck"
        self.makeappx = self.root / "MakeAppx.exe"
        self.exe_bytes = b"synthetic-exe-fixture-not-product"
        self.pck_bytes = b"synthetic-pck-fixture-not-product"
        self.makeappx_bytes = b"synthetic-makeappx-fixture-not-executable"
        self.exe.write_bytes(self.exe_bytes)
        self.pck.write_bytes(self.pck_bytes)
        self.makeappx.write_bytes(self.makeappx_bytes)
        self.patches = [
            patch.object(builder, "EXE_SHA256", digest(self.exe_bytes)),
            patch.object(builder, "PCK_SHA256", digest(self.pck_bytes)),
            patch.object(builder, "EXPECTED_EXE_SIZE", len(self.exe_bytes)),
            patch.object(builder, "EXPECTED_PCK_SIZE", len(self.pck_bytes)),
            patch.object(builder, "MAKEAPPX_SHA256", digest(self.makeappx_bytes)),
            patch.object(builder, "MAKEAPPX_FILE_VERSION", "fixture-version-only"),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

        self.identity = {
            "store_id": "AB12CD34EF56",
            "reserved_display_name": "Prism Route 3D",
            "package_identity_name": "Example.PrismRoute3D",
            "publisher": "CN=11111111-2222-3333-4444-555555555555",
            "publisher_display_name": "Example Publisher",
            "pfn": "Example.PrismRoute3D_abc123def4567",
            "package_sid": "S-1-15-2-1-2-3-4-5-6-7",
        }
        self.identity_return = {
            "schema_version": 1,
            "authority": "MICROSOFT_PARTNER_CENTER_OFFICIAL_UI",
            "approval_status": "APPROVED",
            "official_ui_capture_verified": True,
            "identity_rebind_status": "VERIFIED_CURRENT_SOURCE_CAS",
            "source_sha": builder.SOURCE_SHA,
            "request_id": builder.REQUEST_ID,
            "factory_artifact_id": builder.FACTORY_ARTIFACT_ID,
            "exe_sha256": builder.EXE_SHA256,
            "pck_sha256": builder.PCK_SHA256,
            "capture_receipt_sha256": "a" * 64,
            "operator_attested": True,
            "operator": "test operator",
            "retrieved_at_utc": "2026-11-28T00:00:00Z",
            "package_version": "1.2.3.4",
            "identity": copy.deepcopy(self.identity),
        }
        self.identity_capture_receipt = {
            "receipt_type": "PRISM_CURRENT_SOURCE_IDENTITY_CAPTURE",
            "authority": "MICROSOFT_PARTNER_CENTER_OFFICIAL_UI",
            "official_ui_capture_verified": True,
            "identity_rebind_status": "VERIFIED_CURRENT_SOURCE_CAS",
            "source_sha": builder.SOURCE_SHA,
            "request_id": builder.REQUEST_ID,
            "factory_artifact_id": builder.FACTORY_ARTIFACT_ID,
            "exe_sha256": builder.EXE_SHA256,
            "pck_sha256": builder.PCK_SHA256,
            "captured_at_utc": "2026-11-28T00:00:00Z",
            "operator_attested": True,
            "operator": "test operator",
            "identity": copy.deepcopy(self.identity),
            "package_version": "1.2.3.4",
        }
        self.identity_capture_raw = json.dumps(
            self.identity_capture_receipt, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.identity_return["capture_receipt_sha256"] = digest(self.identity_capture_raw)
        self.identity_raw = json.dumps(
            self.identity_return, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.version_return = {
            "schema_version": 1,
            "authority": "PARTNER_CENTER_APPROVED_IDENTITY_RETURN",
            "approval_status": "APPROVED",
            "source_sha": builder.SOURCE_SHA,
            "request_id": builder.REQUEST_ID,
            "identity_return_sha256": digest(self.identity_raw),
            "retrieved_at_utc": "2026-11-28T00:01:00Z",
            "package_version": "1.2.3.4",
            **copy.deepcopy(self.identity),
        }
        self.binding = {
            "schema_version": 1,
            "source_sha": builder.SOURCE_SHA,
            "request_id": builder.REQUEST_ID,
            "registration_type": builder.REGISTRATION_TYPE,
            "identity": copy.deepcopy(self.identity),
            "package_version": "1.2.3.4",
        }

        self.asset_root = self.root / "assets"
        self.asset_root.mkdir()
        self.asset_approval = {
            "schema_version": 1,
            "approval_status": "USER_APPROVED",
            "source_sha": builder.SOURCE_SHA,
            "request_id": builder.REQUEST_ID,
            "approved_by": "test asset approver",
            "approval_reference": "fixture-only approval reference",
            "assets": {},
        }
        for relative, dimensions in builder.EXPECTED_ASSETS.items():
            data = png_bytes(*dimensions)
            path = self.asset_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.asset_approval["assets"][relative] = {
                "approved": True,
                "path": relative,
                "width": dimensions[0],
                "height": dimensions[1],
                "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
                "sha256": digest(data),
            }

        self.manifest = self.root / "AppxManifest.xml"
        self.write_manifest()
        self.handoff = json.loads(
            (Path(__file__).resolve().parents[1]
             / "handoffs/prism-route-3d-current-source-package-readiness-20261128.json")
            .read_text(encoding="utf-8")
        )
        self.makeappx_receipt = {
            "path": str(self.makeappx.resolve()),
            "file_version": "fixture-version-only",
            "sha256": digest(self.makeappx_bytes),
            "authenticode_status": "Valid",
            "signer_subject": "CN=Microsoft Corporation",
            "help_probe_invoked": True,
            "help_probe_contains_pack_usage": True,
            "makeappx_pack_invoked": False,
            "product_msix_created": False,
        }

    def write_manifest(self, *, publisher=None, version="1.2.3.4"):
        publisher = publisher or self.identity["publisher"]
        xml = f'''<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="{builder.APPX_NS}"
         xmlns:uap="{builder.UAP_NS}"
         xmlns:rescap="{builder.RESCAP_NS}">
  <Identity Name="{self.identity["package_identity_name"]}"
            Publisher="{publisher}"
            Version="{version}"
            ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Prism Route 3D</DisplayName>
    <PublisherDisplayName>{self.identity["publisher_display_name"]}</PublisherDisplayName>
    <Logo>Assets/StoreLogo.png</Logo>
  </Properties>
  <Applications>
    <Application Id="PrismRoute3D"
                 Executable="VFS/ProgramFilesX64/PrismRoute3D/candidate.exe"
                 EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Prism Route 3D"
                          Square150x150Logo="Assets/Square150x150Logo.png"
                          Square44x44Logo="Assets/Square44x44Logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
'''
        self.manifest.write_text(xml, encoding="utf-8")

    def inputs(self):
        return {
            "handoff": self.handoff,
            "identity_return": self.identity_return,
            "identity_raw": self.identity_raw,
            "identity_capture_receipt": self.identity_capture_receipt,
            "identity_capture_raw": self.identity_capture_raw,
            "version_return": self.version_return,
            "package_binding": self.binding,
            "asset_approval": self.asset_approval,
            "asset_root": self.asset_root,
            "manifest_path": self.manifest,
            "exe_path": self.exe,
            "pck_path": self.pck,
            "makeappx_receipt": self.makeappx_receipt,
            "makeappx_path": self.makeappx,
        }

    def validate(self, **changes):
        values = self.inputs()
        values.update(changes)
        return builder.validate_build_inputs(**values)

    def test_complete_synthetic_fixture_validates_but_creates_no_package(self):
        result = self.validate()
        self.assertEqual(
            result["status"],
            "ALL_PRODUCT_MSIX_BUILD_GATES_VALIDATED_NO_PACKAGE_CREATED",
        )
        self.assertFalse(result["product_msix_created"])
        self.assertFalse(result["store_submission_allowed"])

    def test_missing_identity_is_rejected(self):
        with self.assertRaisesRegex(builder.BuildGateError, "Identity return is missing"):
            self.validate(identity_return=None)

    def test_stale_identity_source_is_rejected(self):
        bad = copy.deepcopy(self.identity_return)
        bad["source_sha"] = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
        with self.assertRaisesRegex(builder.BuildGateError, "Identity source SHA"):
            self.validate(identity_return=bad)

    def test_missing_or_drifted_official_capture_receipt_is_rejected(self):
        with self.assertRaisesRegex(builder.BuildGateError, "capture receipt is missing"):
            self.validate(identity_capture_receipt=None)
        bad = copy.deepcopy(self.identity_capture_receipt)
        bad["source_sha"] = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
        bad_raw = json.dumps(bad, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self.assertRaisesRegex(builder.BuildGateError, "capture receipt binding mismatch"):
            self.validate(identity_capture_receipt=bad, identity_capture_raw=bad_raw)

    def test_identity_capture_receipt_bytes_must_match_pinned_sha(self):
        bad_raw = self.identity_capture_raw + b"tampered"
        with self.assertRaisesRegex(builder.BuildGateError, "capture receipt bytes do not match"):
            self.validate(identity_capture_raw=bad_raw)

    def test_source_or_request_mismatch_is_rejected(self):
        bad_version = copy.deepcopy(self.version_return)
        bad_version["request_id"] = "3d-prism-route-3d-e432d94ed0db"
        with self.assertRaisesRegex(builder.BuildGateError, "Version source/request"):
            self.validate(version_return=bad_version)

    def test_absent_or_invalid_four_part_version_is_rejected(self):
        for value in (None, "", "1.2.3", "1.2.3.70000", "0.0.0.0"):
            with self.subTest(value=value):
                bad_version = copy.deepcopy(self.version_return)
                bad_version["package_version"] = value
                with self.assertRaises(builder.BuildGateError):
                    self.validate(version_return=bad_version)

    def test_version_must_reference_exact_identity_return_bytes(self):
        bad_version = copy.deepcopy(self.version_return)
        bad_version["identity_return_sha256"] = "0" * 64
        with self.assertRaisesRegex(builder.BuildGateError, "exact official Identity return bytes"):
            self.validate(version_return=bad_version)

    def test_publisher_mismatch_is_rejected(self):
        bad = copy.deepcopy(self.binding)
        bad["identity"]["publisher"] = "CN=99999999-9999-9999-9999-999999999999"
        with self.assertRaisesRegex(builder.BuildGateError, "Publisher/PFN/SID"):
            self.validate(package_binding=bad)

    def test_pfn_mismatch_is_rejected(self):
        bad = copy.deepcopy(self.version_return)
        bad["pfn"] = "Wrong.PackageFamily_abc123"
        with self.assertRaisesRegex(builder.BuildGateError, "Version return Identity mismatch: pfn"):
            self.validate(version_return=bad)

    def test_sid_mismatch_is_rejected(self):
        bad = copy.deepcopy(self.binding)
        bad["identity"]["package_sid"] = "S-1-15-2-9-9-9-9-9-9-9"
        with self.assertRaisesRegex(builder.BuildGateError, "Publisher/PFN/SID"):
            self.validate(package_binding=bad)

    def test_missing_store_png_is_rejected(self):
        (self.asset_root / "Assets/StoreLogo.png").unlink()
        with self.assertRaises((builder.BuildGateError, FileNotFoundError)):
            self.validate()

    def test_wrong_store_png_dimensions_are_rejected(self):
        path = self.asset_root / "Assets/StoreLogo.png"
        path.write_bytes(png_bytes(49, 50))
        with self.assertRaisesRegex(builder.BuildGateError, "dimensions mismatch"):
            self.validate()

    def test_store_png_crc_or_sha_drift_is_rejected(self):
        bad = copy.deepcopy(self.asset_approval)
        bad["assets"]["Assets/StoreLogo.png"]["crc32"] = "00000000"
        with self.assertRaisesRegex(builder.BuildGateError, "CRC32 mismatch"):
            self.validate(asset_approval=bad)

    def test_unapproved_store_png_is_rejected(self):
        bad = copy.deepcopy(self.asset_approval)
        bad["assets"]["Assets/Square44x44Logo.png"]["approved"] = False
        with self.assertRaisesRegex(builder.BuildGateError, "not individually approved"):
            self.validate(asset_approval=bad)

    def test_exe_byte_drift_is_rejected(self):
        self.exe.write_bytes(self.exe_bytes + b"drift")
        with self.assertRaisesRegex(builder.BuildGateError, "candidate.exe size or SHA256 drift"):
            self.validate()

    def test_pck_byte_drift_is_rejected(self):
        self.pck.write_bytes(self.pck_bytes + b"drift")
        with self.assertRaisesRegex(builder.BuildGateError, "candidate.pck size or SHA256 drift"):
            self.validate()

    def test_manifest_publisher_or_version_mismatch_is_rejected(self):
        self.write_manifest(publisher="CN=00000000-0000-0000-0000-000000000000")
        with self.assertRaisesRegex(builder.BuildGateError, "AppxManifest Publisher mismatch"):
            self.validate()
        self.write_manifest(version="1.2.3.5")
        with self.assertRaisesRegex(builder.BuildGateError, "AppxManifest Version mismatch"):
            self.validate()

    def test_makeappx_signature_or_digest_drift_is_rejected(self):
        bad = copy.deepcopy(self.makeappx_receipt)
        bad["sha256"] = "0" * 64
        with self.assertRaisesRegex(builder.BuildGateError, "MakeAppx SHA256 mismatch"):
            self.validate(makeappx_receipt=bad)

    def test_fixture_validation_does_not_invoke_makeappx(self):
        result = self.validate()
        self.assertFalse(result["product_msix_created"])

    def test_real_build_requires_protected_approval_before_makeappx(self):
        validated = self.validate()
        with patch.object(builder.subprocess, "run") as run:
            with self.assertRaisesRegex(builder.BuildGateError, "PRISM_MSIX_BUILD_APPROVED"):
                builder.build_unsigned_msix(
                    **self.inputs(),
                    output_path=self.root / "dist" / "product.msix",
                    environment={},
                )
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
