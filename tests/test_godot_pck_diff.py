"""Synthetic Godot 4.3 PCK v2 diff regression: diagnostic never promotes E2E."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from godot_pck_diff import compare_pcks, inventory_pck


def make_pck(path: Path, members: dict[str, bytes], *, version=2, flags=0):
    header = struct.pack("<4sIIIIIQ", b"GDPC", version, 4, 3, 0, flags, 0) + bytes(64)
    names = list(members)
    entry_size = sum(4 + len(n.encode()) + 16 + 16 + 4 for n in names)
    position = len(header) + 4 + entry_size
    directory = struct.pack("<I", len(names))
    data = b""
    for name in names:
        blob = members[name]
        encoded = name.encode()
        directory += struct.pack("<I", len(encoded)) + encoded
        directory += struct.pack("<QQ", position, len(blob))
        directory += hashlib.md5(blob, usedforsecurity=False).digest() + struct.pack("<I", 0)
        position += len(blob)
        data += blob
    path.write_bytes(header + directory + data)


class GodotPckDiffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.a = Path(self.temp.name) / "factory.pck"
        self.b = Path(self.temp.name) / "local.pck"

    def test_byte_identical(self):
        make_pck(self.a, {"res://a.gd": b"alpha"})
        self.b.write_bytes(self.a.read_bytes())
        self.assertEqual(compare_pcks(self.a, self.b)["diagnostic_status"], "BYTE_IDENTICAL")

    def test_member_identical_container_different(self):
        make_pck(self.a, {"res://a.gd": b"alpha", "res://b.gd": b"beta"})
        make_pck(self.b, {"res://b.gd": b"beta", "res://a.gd": b"alpha"})
        self.assertEqual(compare_pcks(self.a, self.b)["diagnostic_status"],
                         "MEMBERS_IDENTICAL_CONTAINER_DIFF")

    def test_member_content_difference(self):
        make_pck(self.a, {"res://a.gd": b"alpha"})
        make_pck(self.b, {"res://a.gd": b"beta"})
        r = compare_pcks(self.a, self.b)
        self.assertEqual((r["diagnostic_status"], r["changed_count"]), ("MEMBER_CONTENT_DIFF", 1))
        self.assertFalse(r["store_submission_allowed"])

    def test_added_member(self):
        make_pck(self.a, {"res://a.gd": b"alpha"})
        make_pck(self.b, {"res://a.gd": b"alpha", "res://b.gd": b"beta"})
        self.assertEqual(compare_pcks(self.a, self.b)["only_in_local_count"], 1)

    def test_bad_member_md5_rejected(self):
        make_pck(self.a, {"res://a.gd": b"alpha"})
        data = bytearray(self.a.read_bytes())
        data[-1] ^= 1
        self.a.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "checksum"):
            inventory_pck(self.a)

    def test_bad_magic_rejected(self):
        make_pck(self.a, {"res://a.gd": b"alpha"})
        data = bytearray(self.a.read_bytes())
        data[0] = 0
        self.a.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            inventory_pck(self.a)

    def test_unsupported_version_rejected(self):
        make_pck(self.a, {"res://a.gd": b"alpha"}, version=3)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            inventory_pck(self.a)

    def test_unsafe_path_rejected(self):
        make_pck(self.a, {"res://../secret": b"x"})
        with self.assertRaisesRegex(ValueError, "unsafe"):
            inventory_pck(self.a)

    def test_truncated_directory_rejected(self):
        make_pck(self.a, {"res://a.gd": b"alpha"})
        self.a.write_bytes(self.a.read_bytes()[:100])
        with self.assertRaisesRegex(ValueError, "truncated"):
            inventory_pck(self.a)


if __name__ == "__main__":
    unittest.main()
