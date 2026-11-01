"""Read-only Prism Sentinel Identity lineage check; never authorizes CAS/Store."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

SENTINEL_SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
SENTINEL_REQUEST = "3d-prism-route-3d-e432d94ed0db"
HISTORICAL_SOURCE = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
HISTORICAL_REQUEST = "3d-prism-route-3d-15fdcb52e46e"
REQUIRED = frozenset(("store_id", "reserved_display_name", "package_identity_name",
                      "publisher", "publisher_display_name", "pfn", "package_sid"))
MAX_JSON_BYTES = 65536


class IdentityLineageError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IdentityLineageError("duplicate JSON key")
        result[key] = value
    return result


def _read(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise IdentityLineageError("missing or oversized JSON")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)


def inspect_lineage(request, inherited):
    """Validate source lineage; a historical reviewed=True is never Sentinel approval."""
    if not isinstance(request, dict) or not isinstance(inherited, dict):
        raise IdentityLineageError("invalid Identity lineage inputs")
    if (request.get("handoff_type") != "GAME_3D_USER_ID_REQUEST"
            or request.get("product_name") != "Prism Route 3D"
            or request.get("slug") != "prism-route-3d"
            or request.get("source_sha") != SENTINEL_SOURCE
            or request.get("request_id") != SENTINEL_REQUEST
            or request.get("factory_build_head") != SENTINEL_SOURCE
            or request.get("registration_type") != "MSIX_OR_PWA_GAME"
            or request.get("partner_center_selection") != "MSIX or PWA game"
            or request.get("packaging_strategy") != "GODOT_WINDOWS_EXE_PCK_TO_MAKEAPPX_STANDARD_MSIX"
            or request.get("allow_local_product_creation") is not False
            or request.get("status") != "USER_ID_REQUEST_REVERIFY_EXISTING_PRODUCT"
            or request.get("source_repository") != "shihuiarenjinba-png/3d-game-factory"
            or request.get("source_branch") != "codex/prism-route-trap-tension-20261029"
            or request.get("partner_center_product_status") != "UNRECONCILED_MANUAL_OBSERVATIONS"
            or request.get("official_identity_capture_status") != "NOT_INDEPENDENTLY_AUTHENTICATED"
            or request.get("approved_package_version") is not None
            or request.get("signed_post_identity_msix_sha256") is not None
            or request.get("windows_all_auto_intake_receipt") is not None
            or request.get("xbox_title_id_scid_msa_app_id_required") is not False
            or request.get("local_windows_gui_gpu_install") != "DEFERRED_LOCAL_GATE"):
        raise IdentityLineageError("pinned Sentinel request mismatch")
    fields = request.get("official_identity_fields_required")
    if not isinstance(fields, dict) or set(fields) != REQUIRED or any(value is not None for value in fields.values()):
        raise IdentityLineageError("request contains missing or purportedly approved official fields")
    historical = request.get("historical_reference_not_current_approval")
    if (not isinstance(historical, dict)
            or historical.get("source_sha") != HISTORICAL_SOURCE
            or historical.get("verified_for_new_source") is not False
            or historical.get("store_id") != "9N95J2T57B41"):
        raise IdentityLineageError("historical reference mismatch")
    cas = request.get("identity_cas_handoff")
    if (not isinstance(cas, dict)
            or cas.get("target") != "products/prism-route-3d/store/approved-identity.json"
            or cas.get("required_new_source_sha") != SENTINEL_SOURCE
            or cas.get("required_new_request_id") != SENTINEL_REQUEST
            or cas.get("official_capture_receipt") is not None
            or cas.get("new_source_cas_receipt") is not None
            or cas.get("status") != "HOLD"
            or request.get("product_e2e") != "HOLD"
            or request.get("store_submission_allowed") is not False):
        raise IdentityLineageError("request falsely claims CAS/Store readiness")
    if (inherited.get("reviewed") is not True
            or inherited.get("source") != "partner_center"
            or inherited.get("slug") != "prism-route-3d"
            or inherited.get("request_id") != HISTORICAL_REQUEST
            or inherited.get("source_sha") != HISTORICAL_SOURCE
            or inherited.get("verified_source_sha") != HISTORICAL_SOURCE
            or inherited.get("expected_head_sha") != HISTORICAL_SOURCE
            or inherited.get("store_id") != historical["store_id"]
            or inherited.get("reserved_display_name") != "Prism Route 3D"
            or inherited.get("name") != "OkinawaDesktopTools.PrismRoute3D"
            or inherited.get("publisher_display_name") != "Okinawa Desktop Tools"):
        raise IdentityLineageError("inherited Identity is not the pinned historical source")
    for field in ("publisher", "package_family_name", "package_sid"):
        if not isinstance(inherited.get(field), str) or not inherited[field].strip():
            raise IdentityLineageError("historical Identity field missing: " + field)
    return {
        "status": "HOLD_HISTORICAL_IDENTITY_NOT_SENTINEL_CAS",
        "product": "Prism Route 3D",
        "source_sha": SENTINEL_SOURCE, "request_id": SENTINEL_REQUEST,
        "historical_source_sha": HISTORICAL_SOURCE,
        "historical_request_id": HISTORICAL_REQUEST,
        "partner_center_product_reverification_required": True,
        "official_identity_capture_authenticated_by_this_check": False,
        "new_source_cas_verified": False, "approved_package_version": None,
        "signed_msix_verified": False, "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD", "store_submission_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--inherited-identity", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = inspect_lineage(_read(args.request), _read(args.inherited_identity))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "HOLD_INVALID_IDENTITY_LINEAGE",
                          "reason": str(exc), "product_e2e": "HOLD",
                          "store_submission_allowed": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
