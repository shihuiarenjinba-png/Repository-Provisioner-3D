"""HOLD-only source selection for the independently audited 2026-11-01 Prism artifacts.

A newer workflow run is not proof of the pinned Sentinel revision. This
validator checks immutable historical byte-audit anchors, not live GitHub
authentication, Store Identity, signing, or permission to submit.
"""
import argparse
import json
from pathlib import Path

RECEIPT = Path(__file__).resolve().parent / "handoffs/prism-route-3d-artifact-source-discrimination-20261101-1325.json"
SENTINEL = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
ORIGINAL = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
SENTINEL_REQUEST = "3d-prism-route-3d-e432d94ed0db"
ORIGINAL_REQUEST = "3d-prism-route-3d-15fdcb52e46e"
EXE_SHA = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
SENTINEL_PCK = "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"
ORIGINAL_PCK = "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"
# role -> (artifact id, run id, ZIP SHA256, ZIP size). Independent audit
# pins, not dynamically trusted values read from the same JSON.
ANCHORS = {
    "factory": (12909162367, 40901053437, "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c", 30880705),
    "sentinel_pre": (12961277866, 41020501779, "516f9dad3375ee8b4d6bc86b98b0542c3a140206de23b9badfe296c0f5a73b8c", 2482),
    "sentinel_unsigned_qa": (12961735943, 41020501832, "d678c0ff7c014f86a3d4ccb6517a9eafa65b409016dc57a650ed3d017c2f3be2", 31032520),
    "new_legacy_pre": (13068198139, 41269051480, "73cdd592eb2be8de96d5c0d7d34ed045bc03907f122934d916f6dfc9de07567d", 4640),
    "new_legacy_unsigned_qa": (13068860574, 41269051453, "02cdb9d1d0ded8cf3fb3845fa82d79b2a6c2b606889d13a57537f054fcf73be0", 31022039),
}
STAGES = {"factory": "factory", "pre": "sentinel_pre", "unsigned_msix": "sentinel_unsigned_qa"}


class SourceGateError(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise SourceGateError(reason)


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate receipt JSON key")
        result[key] = value
    return result


def classify(receipt, *, stage, artifact_id, expected_source_sha):
    """Select an audited Sentinel artifact; never promote to Store-ready."""
    _require(isinstance(receipt, dict), "missing audit")
    _require(receipt.get("schema_version") == "1.0" and
             receipt.get("receipt_type") == "GAME_3D_INDEPENDENT_REAL_ARTIFACT_SOURCE_DISCRIMINATION" and
             receipt.get("product") == "Prism Route 3D" and
             receipt.get("slug") == "prism-route-3d", "wrong audit")
    _require(receipt.get("pinned_source_sha") == SENTINEL and
             receipt.get("pinned_request_id") == SENTINEL_REQUEST and
             receipt.get("factory_build_head") == SENTINEL, "pinned source/request drift")
    records = receipt.get("artifact_checks")
    _require(isinstance(records, dict) and set(records) == set(ANCHORS), "incomplete artifact audit")
    for role, anchor in ANCHORS.items():
        item = records[role]
        _require(isinstance(item, dict) and
                 type(item.get("artifact_id")) is int and
                 type(item.get("run_id")) is int and
                 type(item.get("archive_bytes")) is int and
                 (item["artifact_id"], item["run_id"], item.get("archive_sha256"),
                  item["archive_bytes"]) == anchor, "artifact anchor drift: " + role)
    factory, pre, unsigned = (records[x] for x in ("factory", "sentinel_pre", "sentinel_unsigned_qa"))
    legacy_pre, legacy_msix = (records[x] for x in ("new_legacy_pre", "new_legacy_unsigned_qa"))
    _require(factory.get("exe_sha256") == EXE_SHA and factory.get("exe_bytes") == 84214784 and
             factory.get("pck_sha256") == SENTINEL_PCK and factory.get("pck_bytes") == 71568,
             "Sentinel Factory payload drift")
    _require(pre.get("source_request_match") is True and pre.get("status") == "HOLD" and
             pre.get("official_identity_status") == "UNVERIFIED", "PRE identity not held")
    _require(unsigned.get("evidence_source_sha") == SENTINEL and
             unsigned.get("evidence_request_id") == SENTINEL_REQUEST and
             unsigned.get("exe_sha256") == EXE_SHA and unsigned.get("pck_sha256") == SENTINEL_PCK and
             unsigned.get("exe_matches_sentinel_factory") is True and
             unsigned.get("pck_matches_sentinel_factory") is True and
             unsigned.get("appx_signature_present") is False and
             unsigned.get("fixture_identity") is True, "Sentinel QA payload drift")
    _require(legacy_pre.get("source_sha") == ORIGINAL and
             legacy_pre.get("request_id") == ORIGINAL_REQUEST and
             legacy_msix.get("evidence_source_sha") == ORIGINAL and
             legacy_msix.get("evidence_request_id") == ORIGINAL_REQUEST and
             legacy_msix.get("exe_sha256") == EXE_SHA and
             legacy_msix.get("pck_sha256") == ORIGINAL_PCK and
             legacy_msix.get("pck_bytes") == 39808 and
             legacy_msix.get("exe_matches_sentinel_factory") is True and
             legacy_msix.get("pck_matches_sentinel_factory") is False and
             legacy_msix.get("appx_signature_present") is False and
             legacy_msix.get("fixture_identity") is True, "legacy source discrimination drift")
    decision = receipt.get("decision")
    _require(isinstance(decision, dict) and
             decision.get("new_20261101_workflow_outputs") == "LEGACY_SOURCE_NOT_SENTINEL" and
             decision.get("new_legacy_msix_promotable_to_sentinel") is False and
             decision.get("official_identity_cas") == "HOLD" and
             decision.get("signed_msix") == "HOLD" and
             decision.get("windows_all_auto_intake") == "HOLD" and
             decision.get("product_e2e") == "HOLD" and
             decision.get("store_submission_allowed") is False and
             decision.get("second_3d_product_allowed") is False, "unsafe downstream authorization")
    _require(stage in STAGES, "unknown stage")
    _require(expected_source_sha == SENTINEL, "source is not pinned Sentinel")
    role = STAGES[stage]
    _require(type(artifact_id) is int and artifact_id == ANCHORS[role][0],
             "artifact belongs to another source or stage")
    return {
        "status": "HOLD_HISTORICAL_SENTINEL_SOURCE_CONFIRMED",
        "stage": stage, "artifact_id": artifact_id,
        "source_sha": SENTINEL, "request_id": SENTINEL_REQUEST,
        "live_github_authentication": False,
        "official_identity_cas_verified": False,
        "signed_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD", "store_submission_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, default=RECEIPT)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        if not args.receipt.is_file() or args.receipt.stat().st_size > 65536:
            raise SourceGateError("missing or oversized receipt")
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"),
                             object_pairs_hook=_no_duplicate_keys)
        result = classify(receipt, stage=args.stage, artifact_id=args.artifact_id,
                          expected_source_sha=args.source_sha)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc),
                          "store_submission_allowed": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
