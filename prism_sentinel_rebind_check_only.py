"""Prism Route 3D Sentinel read-only rebind handoff for the 36-minute owner.

This correlates the independently downloaded historical Factory receipt with
Provisioner and optionally *live* artifact metadata. UI capture is structural
input, never Partner Center authentication. CAS and Store always remain HOLD.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from prism_sentinel_factory_receipt_contract import check as check_factory, ContractError
from prism_sentinel_identity_preflight import (
    check as check_identity, PreflightError, EXPECTED, IDENTITY_MATCH,
    LEGACY_COMMIT, LEGACY_SOURCE,
)

class RebindError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise RebindError(message)

def make_check_only(receipt, handoff, capture=None, live_artifact=None):
    """Fail closed on drift. Return a machine-readable HOLD, never an approval."""
    try:
        factory = check_factory(receipt, handoff)
    except ContractError as exc:
        raise RebindError("Factory/Provisioner correlation: " + str(exc)) from exc
    require(factory["factory_receipt_structurally_correlated"] is True,
            "Factory receipt not correlated")
    live = False
    if live_artifact is not None:
        require(type(live_artifact) is dict, "invalid live artifact metadata")
        a = receipt["artifact"]
        for key, expected in (
            ("id", EXPECTED["factory_artifact_id"]),
            ("size_in_bytes", a["archive_size_bytes"]),
            ("digest", "sha256:" + EXPECTED["factory_archive_sha256"]),
            ("expires_at", a["expires_at"]),
        ):
            require(type(live_artifact.get(key)) is type(expected) and
                    live_artifact[key] == expected, "live artifact drift: " + key)
        require(live_artifact.get("expired") is False, "Factory artifact expired")
        require(type(live_artifact.get("workflow_run")) is dict and
                live_artifact["workflow_run"].get("head_sha") == EXPECTED["source_sha"],
                "live workflow source mismatch")
        live = True
    # The Factory receipt was independently byte-verified earlier. This
    # adapter is only legal after check_factory has compared those exact bytes.
    flat = dict(EXPECTED, fixture_identity=False, signature_present=False,
                product_msix=False)
    try:
        preflight = check_identity(flat, capture)
    except PreflightError as exc:
        raise RebindError("Identity capture: " + str(exc)) from exc
    require(preflight["official_identity_cas_verified"] is False and
            preflight["store_submission_allowed"] is False, "unauthorized CAS claim")
    return {
        "handoff_type": "PRISM_SENTINEL_REBIND_CHECK_ONLY",
        "read_only": True,
        "next_owner": "36-minute Windows/E2E Identity UI/CAS lane",
        "product_name": EXPECTED["product_name"],
        "slug": EXPECTED["slug"],
        "source_sha": EXPECTED["source_sha"],
        "request_id": EXPECTED["request_id"],
        "factory_build_head": EXPECTED["factory_build_head"],
        "factory_run_id": EXPECTED["factory_run_id"],
        "factory_artifact_id": EXPECTED["factory_artifact_id"],
        "factory_artifact_live_metadata_checked": live,
        "exe_sha256": EXPECTED["exe_sha256"],
        "pck_sha256": EXPECTED["pck_sha256"],
        "registration_type": EXPECTED["registration_type"],
        "partner_center_selection": EXPECTED["partner_center_selection"],
        "store_id_historical_reference_only": IDENTITY_MATCH["store_id"],
        "historical_identity_commit": LEGACY_COMMIT,
        "historical_identity_source_sha": LEGACY_SOURCE,
        "historical_identity_available": True,
        "historical_identity_verified_for_sentinel": False,
        "identity_return_target": EXPECTED["identity_return_target"],
        "required_official_ui_fields": [
            "Store ID", "reserved display name", "Package Identity Name",
            "Publisher", "Publisher Display Name", "PFN", "Package SID",
            "capture reference",
        ],
        "identity_capture_structurally_correlated":
            preflight["identity_fields_structurally_correlated"],
        "status": preflight["status"],
        "official_identity_cas": "HOLD",
        "package_version": "HOLD",
        "signed_product_msix": "HOLD",
        "windows_all_auto_intake": "HOLD",
        "product_e2e": "HOLD",
        "local_windows_gate": "DEFERRED_LOCAL_GATE",
        "store_submission_allowed": False,
        "second_3d_product_allowed": False,
        "limitations": "Check-only correlation, not live Partner Center authentication or CAS.",
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", default="handoffs/prism-sentinel-factory-live-recheck-20261102.json")
    parser.add_argument("--handoff", default="handoffs/prism-sentinel-qa-consumer-20261102.json")
    parser.add_argument("--capture", help="Optional UI capture JSON; never grants CAS")
    parser.add_argument("--live-artifact", help="Optional fresh GitHub artifact metadata JSON")
    args = parser.parse_args()
    def load(path):
        return json.loads(Path(path).read_text(encoding="utf-8")) if path else None
    print(json.dumps(make_check_only(load(args.receipt), load(args.handoff),
                                     load(args.capture), load(args.live_artifact)),
                     ensure_ascii=False, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
