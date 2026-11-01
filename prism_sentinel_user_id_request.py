"""Read-only USER_ID_REQUEST for the pinned Prism Route 3D Sentinel revision.

This prepares a machine-readable operator request. It does not access Partner
Center, authenticate historical Identity, perform CAS, build MSIX, or authorize
Windows intake/Store submission. Historical values are references only.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path

from prism_revision_handoff_contract import (
    RevisionHandoffError, validate_revision_handoff,
)

DEFAULT_HANDOFF = (
    Path(__file__).resolve().parent
    / "handoffs/prism-route-3d-sentinel-revision-20261029.json"
)
REQUIRED_FIELDS = (
    "store_id", "reserved_display_name", "package_identity_name",
    "publisher", "publisher_display_name", "pfn", "package_sid",
)


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RevisionHandoffError("duplicate USER_ID_REQUEST input key")
        result[key] = value
    return result


def build_user_id_request(handoff: dict, *, now: datetime | None = None) -> dict:
    """Build a HOLD-only request from the pinned source and PRE contract.

    Artifact expiry does not prevent *asking* for official Identity, but it
    must be checked again before any artifact consumption or package build.
    """
    validate_revision_handoff(handoff, now=now, require_unexpired=False)
    reference = handoff.get("existing_store_id_reference_unverified")
    if reference != "9N95J2T57B41":
        raise RevisionHandoffError("historical Store ID reference drift")
    original = handoff["immutable_original_provenance"]
    factory = handoff["evidence"]["factory"]
    if factory["run_head_sha"] != handoff["source_sha"]:
        raise RevisionHandoffError("Factory build/source mismatch")
    return {
        "schema_version": "1.0",
        "handoff_type": "GAME_3D_USER_ID_REQUEST",
        "status": "USER_ID_REQUEST_REVERIFY_EXISTING_PRODUCT",
        "product_name": handoff["product"],
        "slug": handoff["slug"],
        "source_repository": handoff["source_repository"],
        "source_branch": handoff["source_branch"],
        "source_sha": handoff["source_sha"],
        "request_id": handoff["request_id"],
        "factory_build_head": factory["run_head_sha"],
        "factory_run_id": factory["run_id"],
        "factory_artifact_id": factory["artifact_id"],
        "packaging_strategy": handoff["packaging_strategy"],
        "registration_type": handoff["registration_type"],
        "partner_center_selection": handoff["partner_center_selection"],
        "partner_center_product_status": handoff["partner_center_product_status"],
        "allow_local_product_creation": False,
        "official_identity_fields_required": {key: None for key in REQUIRED_FIELDS},
        "official_identity_capture_status": "NOT_INDEPENDENTLY_AUTHENTICATED",
        "historical_reference_not_current_approval": {
            "store_id": reference,
            "source_sha": original["source_sha"],
            "identity_reference_commit": original["identity_reference_commit"],
            "verified_for_new_source": False,
        },
        "identity_cas_handoff": {
            "target": handoff["identity_return_target"],
            "required_new_source_sha": handoff["source_sha"],
            "required_new_request_id": handoff["request_id"],
            "official_capture_receipt": None,
            "new_source_cas_receipt": None,
            "status": "HOLD",
        },
        "xbox_title_id_scid_msa_app_id_required": False,
        "artifact_freshness_recheck_required_before_consumption": True,
        "approved_package_version": None,
        "signed_post_identity_msix_sha256": None,
        "windows_all_auto_intake_receipt": None,
        "local_windows_gui_gpu_install": "DEFERRED_LOCAL_GATE",
        "product_e2e": "HOLD",
        "store_submission_allowed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, default=DEFAULT_HANDOFF)
    args = parser.parse_args(argv)
    try:
        if not args.handoff.is_file() or args.handoff.stat().st_size > 65536:
            raise RevisionHandoffError("missing or oversized handoff")
        handoff = json.loads(
            args.handoff.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        result = build_user_id_request(handoff)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({
            "status": "HOLD_INVALID_USER_ID_REQUEST_INPUT",
            "reason": type(exc).__name__,
            "store_submission_allowed": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
