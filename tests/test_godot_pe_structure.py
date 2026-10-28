"""Regression: a Godot Windows x64 export must be a real PE32+ image, not MZ text.

Synthetic PE headers are deliberately non-executable and are never product evidence.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from package_identity_provisioner import HoldError, PackageBuilder, inspect_package


def fake_pe_x64(marker=b""):
    """Minimal structurally coherent x64 PE32+ fixture (not runnable)."""
    data = bytearray(512)
    data[:2] = b"MZ"
    data[0x3c:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x8664).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xf0).to_bytes(2, "little")
    data[0x98:0x9a] = (0x20b).to_bytes(2, "little")
    return bytes(data) + marker


class GodotPeStructureTests(unittest.TestCase):
    def inspect(self, raw):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "candidate.exe"
            exe.write_bytes(raw)
            return inspect_package(exe, godot_export=True)

    def test_valid_minimal_x64_pe32_plus_is_accepted_as_local_evidence_only(self):
        result = self.inspect(fake_pe_x64())
        self.assertEqual(result["godot_export"]["evidence_scope"], "LOCAL_EXPORT_NOT_INDEPENDENT")

    def test_mz_only_is_not_a_windows_pe(self):
        with self.assertRaisesRegex(HoldError, "PE|DOS"):
            self.inspect(b"MZ-fake-windows-binary")

    def test_corrupt_pe_signature_is_rejected(self):
        data = bytearray(fake_pe_x64())
        data[0x80:0x84] = b"NOPE"
        with self.assertRaisesRegex(HoldError, "PE"):
            self.inspect(bytes(data))

    def test_x86_machine_is_rejected(self):
        data = bytearray(fake_pe_x64())
        data[0x84:0x86] = (0x14c).to_bytes(2, "little")
        with self.assertRaisesRegex(HoldError, "x64|machine|PE"):
            self.inspect(bytes(data))

    def test_pe32_instead_of_pe32_plus_is_rejected(self):
        data = bytearray(fake_pe_x64())
        data[0x98:0x9a] = (0x10b).to_bytes(2, "little")
        with self.assertRaisesRegex(HoldError, "PE32|optional|PE"):
            self.inspect(bytes(data))

    def test_section_table_outside_file_is_rejected(self):
        data = bytearray(fake_pe_x64())
        data[0x86:0x88] = (96).to_bytes(2, "little")
        with self.assertRaisesRegex(HoldError, "section|PE"):
            self.inspect(bytes(data))

    def test_section_raw_data_past_end_of_file_is_rejected(self):
        data = bytearray(fake_pe_x64())
        # PE section table starts at 0x80 + 24 + 0xf0 = 0x188.
        data[0x188 + 16:0x188 + 20] = (64).to_bytes(4, "little")
        data[0x188 + 20:0x188 + 24] = (0x300).to_bytes(4, "little")
        with self.assertRaisesRegex(HoldError, "section|raw|PE"):
            self.inspect(bytes(data))

    def test_section_raw_data_with_zero_file_pointer_is_rejected(self):
        data = bytearray(fake_pe_x64())
        data[0x188 + 16:0x188 + 20] = (64).to_bytes(4, "little")
        data[0x188 + 20:0x188 + 24] = (0).to_bytes(4, "little")
        with self.assertRaisesRegex(HoldError, "section|raw|PE"):
            self.inspect(bytes(data))

    def test_bounded_section_raw_data_is_accepted_as_static_evidence_only(self):
        data = bytearray(fake_pe_x64())
        data[0x188 + 16:0x188 + 20] = (32).to_bytes(4, "little")
        data[0x188 + 20:0x188 + 24] = (0x1c0).to_bytes(4, "little")
        self.assertEqual(self.inspect(bytes(data))["godot_export"]["evidence_scope"],
                         "LOCAL_EXPORT_NOT_INDEPENDENT")

    def test_export_rejects_mz_text_before_pck_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, output = root / "project", root / "output"
            source.mkdir()
            output.mkdir()
            (source / "project.godot").write_text('run/main_scene="res://main.tscn"', encoding="utf-8")
            (source / "export_presets.cfg").write_text(
                '[preset.0]\nname="Windows Desktop"\n[preset.0.options]\nbinary_format/embed_pck=false\n',
                encoding="utf-8",
            )
            def fake_run(command, _cwd, _timeout):
                Path(command[-1]).write_bytes(b"MZ-not-a-real-PE")
            with patch.dict(os.environ, {"GODOT_EXE": "godot-mock"}), patch.object(
                PackageBuilder, "_run", side_effect=fake_run
            ):
                with self.assertRaisesRegex(HoldError, "PE|DOS"):
                    PackageBuilder()._build_godot(source, output)


if __name__ == "__main__":
    unittest.main()
