"""Synthetic positive/negative ZIP tests. Positive means byte gate only, NOT Store."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from prism_sentinel_live_zip_handoff import check_zip, GateError, PINNED

BEFORE = datetime(2026, 11, 2, tzinfo=timezone.utc)


class TestLiveZipGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "test.zip"
        self.manifest = {
            "source_sha": PINNED["source_sha"], "request_id": PINNED["request_id"],
            "factory_build_head": PINNED["source_sha"],
            "source_branch": PINNED["source_branch"],
            "source_repository": PINNED["source_repository"],
            "slug": PINNED["slug"], "product_type": "GAME_3D",
            "exe_path": "candidate.exe", "pck_path": "candidate.pck",
            "schema_version": 1,
        }
        self.exe, self.pck = b"test executable", b"new sentinel PCK"
        self.expected = None

    def make(self, *, extra=False):
        pck = self.pck
        self.manifest.update(exe_sha256=hashlib.sha256(self.exe).hexdigest(),
                             pck_sha256=hashlib.sha256(pck).hexdigest(),
                             exe_size_bytes=len(self.exe), pck_size_bytes=len(pck))
        raw_manifest = json.dumps(self.manifest).encode()
        files = {"candidate.exe": self.exe, "candidate.pck": pck,
                 "export-evidence.json": raw_manifest}
        with zipfile.ZipFile(self.path, "w") as z:
            for name, raw in files.items():
                z.writestr(name, raw)
            if extra:
                z.writestr("other.txt", b"unexpected")
        data = self.path.read_bytes()
        self.expected = dict(PINNED, archive_size=len(data),
                             archive_sha256=hashlib.sha256(data).hexdigest(),
                             members={k: (len(v), hashlib.sha256(v).hexdigest())
                                      for k, v in files.items()})

    def test_positive_byte_fixture_still_holds_store(self):
        self.make()
        result = check_zip(self.path, expected=self.expected, now=BEFORE)
        self.assertTrue(result["archive_bytes_verified_this_run"])
        self.assertEqual(result["official_identity_cas"], "HOLD")
        self.assertEqual(result["signed_product_msix"], "HOLD")
        self.assertFalse(result["store_submission_allowed"])

    def test_archive_mutation_rejected(self):
        self.make()
        self.path.write_bytes(self.path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(GateError, "size drift"):
            check_zip(self.path, expected=self.expected, now=BEFORE)

    def test_wrong_pck_sha_rejected(self):
        self.make()
        self.expected["members"]["candidate.pck"] = (len(self.pck), "0" * 64)
        with self.assertRaisesRegex(GateError, "member SHA drift"):
            check_zip(self.path, expected=self.expected, now=BEFORE)

    def test_source_and_request_drift_rejected(self):
        for key in ("source_sha", "request_id", "factory_build_head"):
            with self.subTest(key=key):
                self.manifest[key] = "wrong"
                self.make()
                with self.assertRaisesRegex(GateError, "manifest/source/request/build drift"):
                    check_zip(self.path, expected=self.expected, now=BEFORE)
                self.manifest[key] = (PINNED["source_sha"] if key != "request_id"
                                      else PINNED["request_id"])

    def test_unexpected_member_rejected(self):
        self.make(extra=True)
        with self.assertRaisesRegex(GateError, "ZIP members"):
            check_zip(self.path, expected=self.expected, now=BEFORE)

    def live(self):
        return {"id": self.expected["artifact_id"],
                "size_in_bytes": self.expected["archive_size"],
                "digest": "sha256:" + self.expected["archive_sha256"],
                "expires_at": self.expected["expires_at"], "expired": False,
                "workflow_run": {"head_sha": self.expected["source_sha"]}}

    def test_expired_even_if_metadata_says_not_expired(self):
        self.make()
        with self.assertRaisesRegex(GateError, "expired by UTC deadline"):
            check_zip(self.path, expected=self.expected, live_metadata=self.live(),
                      now=datetime(2026, 11, 6, tzinfo=timezone.utc))

    def test_wrong_live_artifact_and_head_rejected(self):
        self.make()
        for key, val in (("id", 1), ("digest", "sha256:bad"), ("expired", True)):
            with self.subTest(key=key):
                m = self.live()
                m[key] = val
                with self.assertRaisesRegex(GateError, "live GitHub metadata mismatch"):
                    check_zip(self.path, expected=self.expected, live_metadata=m, now=BEFORE)
        m = self.live()
        m["workflow_run"]["head_sha"] = "legacy"
        with self.assertRaises(GateError):
            check_zip(self.path, expected=self.expected, live_metadata=m, now=BEFORE)

    def test_live_positive_still_hold(self):
        self.make()
        r = check_zip(self.path, expected=self.expected, live_metadata=self.live(), now=BEFORE)
        self.assertTrue(r["live_artifact_metadata_checked"])
        self.assertEqual(r["product_e2e"], "HOLD")


if __name__ == "__main__":
    unittest.main()
