"""Fail-closed regression: old Partner Center Identity never approves Sentinel."""
import json
import unittest
from prism_identity_provenance import (
    HistoricalIdentityError, inspect_historical_identity, load_record,
    ORIGINAL_SOURCE_SHA, SENTINEL_SOURCE_SHA,
)


def sample():
    return {
        "reviewed": True, "source": "partner_center",
        "request_id": "3d-prism-route-3d-15fdcb52e46e", "product_type": "GAME_3D",
        "source_factory": "3d-game-factory", "source_repository": "shihuiarenjinba-png/3d-game-factory",
        "source_branch": "codex/3d-canary-prism-route-20261028", "slug": "prism-route-3d",
        "store_id": "9N95J2T57B41", "reserved_display_name": "Prism Route 3D",
        "name": "OkinawaDesktopTools.PrismRoute3D",
        "publisher": "CN=46263F21-A700-41DB-8C9B-114C22FB82FC",
        "publisher_display_name": "Okinawa Desktop Tools",
        "package_family_name": "OkinawaDesktopTools.PrismRoute3D_j8yefg9jgfh58",
        "package_sid": "S-1-15-2-3208955418-98022013-46623760-1876997759-863416391-822502142-2643662492",
        "source_sha": ORIGINAL_SOURCE_SHA, "verified_source_sha": ORIGINAL_SOURCE_SHA,
        "expected_head_sha": ORIGINAL_SOURCE_SHA, "signature_status": "PRE_IDENTITY_EXE_NOT_MSIX",
        "local_signature_status": "PRE_IDENTITY_EXE_NOT_MSIX", "local_package_kind": "exe",
        "package_version_gate": "HOLD", "job_origin": "GITHUB_PRE_IDENTITY_QUEUE",
        "central_repository": "shihuiarenjinba-png/Windows-all-auto",
        "verified_by": "LOCAL_WINDOWS_PARTNER_CENTER_OPERATOR",
        "package_sha256": "a" * 64, "local_package_sha256": "a" * 64,
    }


class HistoricalIdentityTests(unittest.TestCase):
    def test_valid_historical_is_never_approval(self):
        result = inspect_historical_identity(sample())
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["new_revision_cas_verified"])
        self.assertFalse(result["partner_center_record_claim_is_live_authenticated"])
        self.assertEqual(result["sentinel_source_sha"], SENTINEL_SOURCE_SHA)

    def test_reject_new_revision_source_relabel(self):
        item = sample(); item["source_sha"] = SENTINEL_SOURCE_SHA
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_new_request_relabel(self):
        item = sample(); item["request_id"] = "3d-prism-route-3d-e432d94ed0db"
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_signature_promotion(self):
        item = sample(); item["signature_status"] = "SIGNED_MSIX"
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_package_version_promotion(self):
        item = sample(); item["package_version_gate"] = "PASS"
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_cross_product_pfn(self):
        item = sample(); item["package_family_name"] = "Wrong.App_123"
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_digest_mismatch(self):
        item = sample(); item["local_package_sha256"] = "b" * 64
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_unreviewed(self):
        item = sample(); item["reviewed"] = False
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_invalid_sid(self):
        item = sample(); item["package_sid"] = "not-a-sid"
        with self.assertRaises(HistoricalIdentityError): inspect_historical_identity(item)

    def test_reject_duplicate_keys(self):
        with self.assertRaises(HistoricalIdentityError): load_record('{"source_sha":"a","source_sha":"b"}')

    def test_reject_non_object(self):
        with self.assertRaises(HistoricalIdentityError): load_record('[]')

    def test_json_roundtrip(self):
        self.assertEqual(inspect_historical_identity(load_record(json.dumps(sample())))["product_e2e"], "HOLD")


if __name__ == "__main__":
    unittest.main()
