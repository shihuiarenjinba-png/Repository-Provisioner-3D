"""Regression checks: 3D Factory products live under products/<slug>.

These tests never invoke a real Godot binary, Partner Center, or GitHub writes.
"""
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from package_identity_provisioner import HoldError, PackageBuilder, ProductConfig


CONFIG = ProductConfig.load(Path(__file__).resolve().parents[1] / "config.json")


def make_project(root: Path, slug: str) -> Path:
    project = root / "products" / slug
    project.mkdir(parents=True)
    (project / "project.godot").write_text(
        '[application]\nrun/main_scene="res://scenes/main.tscn"\n', encoding="utf-8"
    )
    (project / "export_presets.cfg").write_text(
        '[preset.0]\nname="Windows Desktop"\nplatform="Windows Desktop"\n',
        encoding="utf-8",
    )
    return project


class ProductScopedGodotTests(unittest.TestCase):
    def test_export_uses_only_selected_product_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "factory"
            project = make_project(source, "sample-product")
            other = make_project(source, "other-product")
            (other / "unrelated.exe").write_bytes(b"MZwrong")
            (source / "stale.exe").write_bytes(b"MZstale")
            output = Path(tmp) / "artifacts"
            calls = []

            def fake_run(command, cwd, timeout):
                calls.append((command, cwd, timeout))
                Path(command[-1]).write_bytes(b"MZnew")

            with patch.dict(os.environ, {"GODOT_EXE": "fake-godot"}):
                with patch.object(PackageBuilder, "_run", side_effect=fake_run):
                    selected = PackageBuilder().build(
                        SimpleNamespace(slug="sample-product"), source, output, CONFIG
                    )

            self.assertEqual(selected, (output / "candidate.exe").resolve())
            self.assertEqual(selected.read_bytes(), b"MZnew")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0][3], str(project))
            self.assertEqual(calls[0][1], project)
            self.assertEqual(calls[0][0][-1], str(output / "candidate.exe"))
            self.assertEqual(selected.suffix, ".exe")  # Not a Store-ready MSIX.

    def test_unrelated_output_exe_cannot_replace_current_godot_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "factory"
            make_project(source, "sample-product")
            output = root / "artifacts"
            output.mkdir()
            unrelated = output / "unrelated.exe"
            unrelated.write_bytes(b"MZ-unrelated")
            # An unrelated artifact can have a later mtime than the new export.
            os.utime(unrelated, (4102444800, 4102444800))

            def fake_run(command, cwd, timeout):
                Path(command[-1]).write_bytes(b"MZ-current")

            with patch.dict(os.environ, {"GODOT_EXE": "fake-godot"}), patch.object(
                PackageBuilder, "_run", side_effect=fake_run
            ):
                selected = PackageBuilder().build(
                    SimpleNamespace(slug="sample-product"), source, output, CONFIG
                )
            self.assertEqual(selected, (output / "candidate.exe").resolve())
            self.assertEqual(selected.read_bytes(), b"MZ-current")

    def test_missing_product_does_not_export_factory_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "factory"
            source.mkdir()
            (source / "project.godot").write_text("run/main_scene=x", encoding="utf-8")
            (source / "export_presets.cfg").write_text("Windows Desktop", encoding="utf-8")
            (source / "unrelated.exe").write_bytes(b"MZ")
            with patch.object(PackageBuilder, "_run") as run:
                with self.assertRaisesRegex(HoldError, "product directory"):
                    PackageBuilder().build(
                        SimpleNamespace(slug="missing-game"),
                        source, Path(tmp) / "out", CONFIG
                    )
            run.assert_not_called()

    def test_symlinked_product_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "factory"
            source.mkdir()
            external = Path(tmp) / "outside"
            external.mkdir()
            (source / "products").mkdir()
            try:
                (source / "products" / "sample-product").symlink_to(
                    external, target_is_directory=True
                )
            except (OSError, NotImplementedError):
                self.skipTest("Creating directory symlinks is not permitted here")
            with self.assertRaises(HoldError):
                PackageBuilder().build(
                    SimpleNamespace(slug="sample-product"),
                    source, Path(tmp) / "out", CONFIG
                )

    def test_symlinked_export_preset_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = make_project(root, "sample-product")
            preset = project / "export_presets.cfg"
            preset.unlink()
            external = root / "outside.cfg"
            external.write_text("Windows Desktop", encoding="utf-8")
            try:
                preset.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("Creating file symlinks is not permitted here")
            with patch.object(PackageBuilder, "_run") as run:
                with self.assertRaisesRegex(HoldError, "symlinked"):
                    PackageBuilder().build(
                        SimpleNamespace(slug="sample-product"),
                        root, root / "out", CONFIG
                    )
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
