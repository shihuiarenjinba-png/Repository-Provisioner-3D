"""Prism Sentinel metadata freshness is not Identity or Store approval."""
import json
from datetime import datetime, timedelta, timezone
import unittest

from prism_20261101_source_gate import ANCHORS, SENTINEL, SENTINEL_REQUEST
from prism_sentinel_artifact_freshness import (
    ArtifactFreshnessError, _no_duplicate_keys, validate,
)

NOW = datetime(2026, 11, 1, 7, 28, tzinfo=timezone.utc)


def snapshot():
    records = {}
    for role in ("factory", "sentinel_pre", "sentinel_unsigned_qa"):
        artifact_id, run_id, digest, size = ANCHORS[role]
        records[role] = {
            "id": artifact_id, "workflow_run": {"id": run_id},
            "digest": "sha256:" + digest, "size_in_bytes": size,
            "expired": False, "expires_at": "2026-11-04T07:31:03Z",
        }
    return {
        "schema_version": "1.0",
        "snapshot_type": "GAME_3D_GITHUB_ARTIFACT_METADATA",
        "source_sha": SENTINEL, "request_id": SENTINEL_REQUEST,
        "checked_at_utc": NOW.isoformat(), "artifacts": records,
    }


class PrismSentinelArtifactFreshnessTests(unittest.TestCase):
    def test_valid_metadata_remains_hold_only(self):
        result = validate(snapshot(), now=NOW)
        self.assertEqual(result["status"], "HOLD_FRESH_METADATA_MATCHES_PINNED_AUDIT")
        self.assertEqual(result["product_e2e"], "HOLD")
        for key in ("metadata_live_authenticated_by_this_script",
                    "zip_bytes_reverified_by_this_script", "official_identity_cas_verified",
                    "signed_msix_verified", "windows_all_auto_intake_verified",
                    "store_submission_allowed"):
            self.assertFalse(result[key])

    def test_legacy_artifact_not_substituted(self):
        data = snapshot()
        data["artifacts"]["sentinel_unsigned_qa"]["id"] = ANCHORS["new_legacy_unsigned_qa"][0]
        with self.assertRaisesRegex(ArtifactFreshnessError, "anchor mismatch"):
            validate(data, now=NOW)

    def test_digest_size_and_run_mismatch_rejected(self):
        for path, value in (("digest", "sha256:" + "a" * 64),
                            ("size_in_bytes", 1), ("id", True)):
            with self.subTest(path=path):
                data = snapshot()
                data["artifacts"]["factory"][path] = value
                with self.assertRaisesRegex(ArtifactFreshnessError, "anchor mismatch"):
                    validate(data, now=NOW)
        data = snapshot()
        data["artifacts"]["factory"]["workflow_run"]["id"] = 123
        with self.assertRaises(ArtifactFreshnessError):
            validate(data, now=NOW)

    def test_expired_unknown_and_near_expiry_rejected(self):
        for expired in (True, None, "false"):
            data = snapshot()
            data["artifacts"]["factory"]["expired"] = expired
            with self.assertRaisesRegex(ArtifactFreshnessError, "expired or unknown"):
                validate(data, now=NOW)
        data = snapshot()
        data["artifacts"]["factory"]["expires_at"] = (NOW + timedelta(minutes=10)).isoformat()
        with self.assertRaisesRegex(ArtifactFreshnessError, "near-expiry"):
            validate(data, now=NOW)

    def test_stale_future_and_naive_timestamps_rejected(self):
        for minutes in (-31, 6):
            data = snapshot()
            data["checked_at_utc"] = (NOW + timedelta(minutes=minutes)).isoformat()
            with self.assertRaisesRegex(ArtifactFreshnessError, "stale or future"):
                validate(data, now=NOW)
        data = snapshot()
        data["checked_at_utc"] = "2026-11-01T07:28:00"
        with self.assertRaisesRegex(ArtifactFreshnessError, "timezone"):
            validate(data, now=NOW)

    def test_source_request_and_missing_role_rejected(self):
        for key in ("source_sha", "request_id"):
            data = snapshot()
            data[key] = "invalid"
            with self.assertRaisesRegex(ArtifactFreshnessError, "source/request"):
                validate(data, now=NOW)
        data = snapshot()
        del data["artifacts"]["factory"]
        with self.assertRaisesRegex(ArtifactFreshnessError, "roles"):
            validate(data, now=NOW)

    def test_nested_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ArtifactFreshnessError, "duplicate"):
            json.loads('{"a":{"id":1,"id":2}}', object_pairs_hook=_no_duplicate_keys)


if __name__ == "__main__":
    unittest.main()
