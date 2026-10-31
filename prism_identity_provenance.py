"""HOLD-only provenance check for Prism Route 3D's historical Partner Center record.

A self-reported historical Identity JSON cannot authorize the Sentinel revision,
signing, Windows intake, or Store submission.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ORIGINAL_SOURCE_SHA = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
SENTINEL_SOURCE_SHA = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
ORIGINAL_REQUEST_ID = "3d-prism-route-3d-15fdcb52e46e"
SENTINEL_REQUEST_ID = "3d-prism-route-3d-e432d94ed0db"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class HistoricalIdentityError(ValueError):
    """The historical record is missing, malformed, or misattributed."""


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise HistoricalIdentityError("duplicate JSON key")
        value[key] = item
    return value


def load_record(raw: str) -> dict:
    try:
        data = json.loads(raw, object_pairs_hook=_unique_pairs)
    except json.JSONDecodeError as exc:
        raise HistoricalIdentityError("invalid JSON") from exc
    if not isinstance(data, dict):
        raise HistoricalIdentityError("Identity record is not an object")
    return data


def inspect_historical_identity(record: dict) -> dict:
    if not isinstance(record, dict):
        raise HistoricalIdentityError("Identity record is not an object")
    expected = {
        "request_id": ORIGINAL_REQUEST_ID,
        "product_type": "GAME_3D",
        "source_factory": "3d-game-factory",
        "source_repository": "shihuiarenjinba-png/3d-game-factory",
        "source_branch": "codex/3d-canary-prism-route-20261028",
        "slug": "prism-route-3d",
        "store_id": "9N95J2T57B41",
        "reserved_display_name": "Prism Route 3D",
        "name": "OkinawaDesktopTools.PrismRoute3D",
        "publisher": "CN=46263F21-A700-41DB-8C9B-114C22FB82FC",
        "publisher_display_name": "Okinawa Desktop Tools",
        "package_family_name": "OkinawaDesktopTools.PrismRoute3D_j8yefg9jgfh58",
        "package_sid": "S-1-15-2-3208955418-98022013-46623760-1876997759-863416391-822502142-2643662492",
        "package_sha256": "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13",
        "local_package_sha256": "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13",
        "source_sha": ORIGINAL_SOURCE_SHA,
        "verified_source_sha": ORIGINAL_SOURCE_SHA,
        "expected_head_sha": ORIGINAL_SOURCE_SHA,
        "signature_status": "PRE_IDENTITY_EXE_NOT_MSIX",
        "local_signature_status": "PRE_IDENTITY_EXE_NOT_MSIX",
        "local_package_kind": "exe",
        "package_version_gate": "HOLD",
        "job_origin": "GITHUB_PRE_IDENTITY_QUEUE",
        "central_repository": "shihuiarenjinba-png/Windows-all-auto",
    }
    for field, value in expected.items():
        if record.get(field) != value:
            raise HistoricalIdentityError("historical Identity field mismatch: " + field)
    if record.get("reviewed") is not True or record.get("source") != "partner_center":
        raise HistoricalIdentityError("historical review claim missing")
    if record.get("verified_by") != "LOCAL_WINDOWS_PARTNER_CENTER_OPERATOR":
        raise HistoricalIdentityError("historical operator claim missing")
    sid = record.get("package_sid")
    if not isinstance(sid, str) or not re.fullmatch(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+", sid):
        raise HistoricalIdentityError("invalid historical package SID")
    package_sha = record.get("package_sha256")
    if (not isinstance(package_sha, str) or not SHA256.fullmatch(package_sha)
            or record.get("local_package_sha256") != package_sha):
        raise HistoricalIdentityError("historical package digest mismatch")
    if ORIGINAL_SOURCE_SHA == SENTINEL_SOURCE_SHA or ORIGINAL_REQUEST_ID == SENTINEL_REQUEST_ID:
        raise HistoricalIdentityError("historical and Sentinel bindings collided")
    return {
        "status": "HISTORICAL_IDENTITY_RECORD_CONSISTENT_HOLD_ONLY",
        "product": "Prism Route 3D",
        "historical_source_sha": ORIGINAL_SOURCE_SHA,
        "historical_request_id": ORIGINAL_REQUEST_ID,
        "sentinel_source_sha": SENTINEL_SOURCE_SHA,
        "sentinel_request_id": SENTINEL_REQUEST_ID,
        "partner_center_record_claim_is_live_authenticated": False,
        "new_revision_cas_verified": False,
        "package_version_approved": False,
        "signed_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "store_submission_allowed": False,
        "product_e2e": "HOLD",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = inspect_historical_identity(load_record(args.input.read_text(encoding="utf-8")))
        code = 0
    except (OSError, UnicodeError, HistoricalIdentityError) as exc:
        receipt = {"status": "HISTORICAL_IDENTITY_UNAVAILABLE_HOLD",
                   "reason": type(exc).__name__, "product_e2e": "HOLD",
                   "store_submission_allowed": False,
                   "new_revision_cas_verified": False}
        code = 2
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
