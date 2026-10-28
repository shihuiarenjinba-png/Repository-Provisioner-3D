"""Regression: relative Provisioner work roots must not break Godot --path."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from package_identity_provisioner import PackageBuilder

class RelativeGodotExportTests(unittest.TestCase):
    def test_godot_receives_absolute_project_and_export_target(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            rel=Path(tmp).relative_to(Path.cwd())
            source=rel/"project"
            out=rel/"output"
            source.mkdir()
            out.mkdir()
            (source/"project.godot").write_text('run/main_scene="res://scenes/main.tscn"')
            (source/"export_presets.cfg").write_text('binary_format/embed_pck=false')
            seen=[]
            def run(command,cwd,timeout):
                seen.append((command,cwd))
                self.assertTrue(Path(command[command.index("--path")+1]).is_absolute())
                self.assertEqual(cwd,source.resolve())
                if "--export-release" in command:
                    target=Path(command[-1])
                    self.assertTrue(target.is_absolute())
                    target.write_bytes(b"MZ"+b"\x00"*4096)
                    target.with_suffix(".pck").write_bytes(b"GDPC"+b"\x00"*128)
            with patch.dict(os.environ,{"GODOT_EXE":"godot-mock"}), patch.object(PackageBuilder,"_run",side_effect=run), patch("package_identity_provisioner._validate_godot_windows_pe_x64"):
                PackageBuilder()._build_godot(source,out)
            self.assertEqual(len(seen),2)
            self.assertIn("--import",seen[0][0])
            self.assertIn("--export-release",seen[1][0])
            self.assertTrue((out/"candidate.exe").is_file())
            self.assertTrue((out/"candidate.pck").is_file())

if __name__=="__main__":
    unittest.main()
