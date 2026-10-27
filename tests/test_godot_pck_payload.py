"""Regression tests: external Godot PCK is part of a complete Windows export."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from package_identity_provisioner import HoldError, PackageBuilder


class GodotPckPayloadTests(unittest.TestCase):
    def make_project(self, root: Path, embed: bool = False) -> tuple[Path, Path]:
        project = root / "product"
        output = root / "artifacts"
        project.mkdir()
        output.mkdir()
        (project / "project.godot").write_text(
            '[application]\nrun/main_scene="res://scenes/main.tscn"\n', encoding="utf-8"
        )
        (project / "export_presets.cfg").write_text(
            '[preset.0]\nname="Windows Desktop"\nplatform="Windows Desktop"\n'
            '[preset.0.options]\nbinary_format/embed_pck='
            + ("true" if embed else "false") + "\n", encoding="utf-8"
        )
        return project, output

    def build(self, project: Path, output: Path, *, exe=True, pck=False, empty_pck=False):
        def fake_export(_command, _cwd, _timeout):
            if exe:
                (output / "candidate.exe").write_bytes(b"MZ-candidate")
            if pck:
                (output / "candidate.pck").write_bytes(b"" if empty_pck else b"GDPC-resources")
        with patch.dict(os.environ, {"GODOT_EXE": "godot-mock"}), patch.object(
            PackageBuilder, "_run", side_effect=fake_export
        ):
            PackageBuilder()._build_godot(project, output)

    def test_external_pck_missing_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp))
            with self.assertRaisesRegex(HoldError, "candidate.pck"):
                self.build(project, output)

    def test_external_pck_empty_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp))
            with self.assertRaisesRegex(HoldError, "candidate.pck"):
                self.build(project, output, pck=True, empty_pck=True)

    def test_external_pck_present_allows_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp))
            self.build(project, output, pck=True)
            self.assertTrue((output / "candidate.pck").is_file())

    def test_external_pck_with_wrong_magic_is_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp))
            def fake_export(_command, _cwd, _timeout):
                (output / "candidate.exe").write_bytes(b"MZ-candidate")
                (output / "candidate.pck").write_bytes(b"NOT_A_GODOT_PACK")
            with patch.dict(os.environ, {"GODOT_EXE": "godot-mock"}), patch.object(
                PackageBuilder, "_run", side_effect=fake_export
            ):
                with self.assertRaisesRegex(HoldError, "PCK.*header"):
                    PackageBuilder()._build_godot(project, output)

    def test_embedded_pck_allows_exe_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp), embed=True)
            self.build(project, output)
            self.assertTrue((output / "candidate.exe").is_file())

    def test_stale_exe_cannot_pass_successful_noop_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp), embed=True)
            (output / "candidate.exe").write_bytes(b"MZ-old-export")
            with patch.dict(os.environ, {"GODOT_EXE": "godot-mock"}), patch.object(
                PackageBuilder, "_run", return_value=None
            ):
                with self.assertRaisesRegex(HoldError, "nonempty executable"):
                    PackageBuilder()._build_godot(project, output)

    def test_stale_external_pck_cannot_pass_new_exe_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp))
            (output / "candidate.pck").write_bytes(b"GDPC-old-export")
            with patch.dict(os.environ, {"GODOT_EXE": "godot-mock"}), patch.object(
                PackageBuilder, "_run",
                side_effect=lambda *_: (output / "candidate.exe").write_bytes(b"MZ-new-export")
            ):
                with self.assertRaisesRegex(HoldError, "candidate.pck"):
                    PackageBuilder()._build_godot(project, output)

    def test_missing_exe_is_hold_even_with_pck(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, output = self.make_project(Path(tmp))
            with self.assertRaisesRegex(HoldError, "nonempty executable"):
                self.build(project, output, exe=False, pck=True)


if __name__ == "__main__":
    unittest.main()
