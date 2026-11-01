"""Prism Sentinel: bind the real-byte Factory audit to the read-only Identity handoff.

This module never authenticates a Partner Center capture or grants CAS, signing,
Version, Store submission or Windows intake. Only the 36-minute owner may
perform independently authenticated UI verification and CAS.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from prism_sentinel_rebind_check_only import make_check_only, RebindError
from prism_sentinel_live_zip_handoff import PINNED, LEGACY_PCK

DEFAULT_BYTE_RECEIPT = "handoffs/prism-sentinel-live-zip-check-only-20261102-0629-jst.json"
DEFAULT_FACTORY_RECEIPT = "handoffs/prism-sentinel-factory-live-recheck-20261102.json"
DEFAULT_PROVISIONER = "handoffs/prism-sentinel-qa-consumer-20261102.json"


class HandoffError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise HandoffError(message)


def utc_time(value):
    require(type(value) is str and value.endswith("Z"), "UTC Z timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HandoffError("invalid UTC timestamp") from exc
    require(parsed.utcoffset().total_seconds() == 0, "UTC timestamp required")
    return parsed


def verify(factory_receipt, provisioner_handoff, byte_receipt,
           capture=None, comparison_reference=None, live_artifact=None,
           now_utc=None):
    """Correlate three independently pinned inputs; fail closed on drift."""
    require(type(byte_receipt) is dict, "missing real Factory ZIP byte receipt")
    current = datetime.now(timezone.utc) if now_utc is None else now_utc
    require(isinstance(current, datetime) and current.tzinfo is not None
            and current.utcoffset() is not None, "timezone-aware time required")
    current = current.astimezone(timezone.utc)
    expiry = utc_time(PINNED["expires_at"])
    audited = utc_time(byte_receipt.get("verified_at_utc"))
    require(audited <= current and audited < expiry and current < expiry,
            "Factory byte audit future-dated or artifact expired")
    anchors = {
        "receipt_type": "PRISM_SENTINEL_LIVE_ZIP_CHECK_ONLY",
        "source_sha": PINNED["source_sha"],
        "request_id": PINNED["request_id"],
        "factory_build_head": PINNED["source_sha"],
        "factory_run_id": PINNED["factory_run_id"],
        "factory_artifact_id": PINNED["artifact_id"],
        "archive_size_bytes": PINNED["archive_size"],
        "archive_sha256": PINNED["archive_sha256"],
        "archive_expires_at_utc": PINNED["expires_at"],
        "registration_type": "MSIX_OR_PWA_GAME",
        "partner_center_selection": "MSIX or PWA game",
        "historical_store_id_reference_only": "9N95J2T57B41",
        "historical_identity_commit_reference_only":
            "11417b75636ee18816028ffd5221884c4c9a9836",
        "legacy_pck_sha256": LEGACY_PCK,
        "identity_return_target": "products/prism-route-3d/store/approved-identity.json",
    }
    for key, expected in anchors.items():
        require(type(byte_receipt.get(key)) is type(expected)
                and byte_receipt[key] == expected, "byte receipt drift: " + key)
    for key in ("zip_crc_pass", "archive_bytes_verified_this_run",
                "manifest_correlated", "source_request_build_head_correlated"):
        require(byte_receipt.get(key) is True, "byte receipt not proven: " + key)
    for key in ("legacy_pck_matches_sentinel",
                "historical_identity_rebound_to_sentinel",
                "unsigned_qa_fixture_is_product", "store_submission_allowed",
                "second_3d_product_allowed"):
        require(byte_receipt.get(key) is False, "unsafe promotion: " + key)
    for key in ("official_identity_cas", "approved_package_version",
                "signed_product_msix", "windows_all_auto_intake", "product_e2e"):
        require(byte_receipt.get(key) == "HOLD", "unsafe downstream status: " + key)
    require(type(byte_receipt.get("members")) is dict
            and set(byte_receipt["members"]) == set(PINNED["members"]),
            "missing or unexpected ZIP member")
    for name, (size, digest) in PINNED["members"].items():
        require(byte_receipt["members"].get(name) ==
                {"size_bytes": size, "sha256": digest},
                "byte receipt member drift: " + name)
    try:
        handoff = make_check_only(factory_receipt, provisioner_handoff, capture,
                                  live_artifact, comparison_reference,
                                  now_utc=current)
    except RebindError as exc:
        raise HandoffError(str(exc)) from exc
    require(handoff["official_identity_cas"] == "HOLD"
            and handoff["signed_product_msix"] == "HOLD"
            and handoff["product_e2e"] == "HOLD"
            and handoff["store_submission_allowed"] is False,
            "unsafe rebind authorization")
    return {
        "handoff_type": "PRISM_SENTINEL_36_IDENTITY_CHECK_ONLY",
        "status": handoff["status"],
        "read_only": True,
        "slug": "prism-route-3d",
        "source_sha": PINNED["source_sha"],
        "request_id": PINNED["request_id"],
        "factory_build_head": PINNED["source_sha"],
        "factory_artifact_id": PINNED["artifact_id"],
        "factory_archive_sha256": PINNED["archive_sha256"],
        "exe_sha256": PINNED["members"]["candidate.exe"][1],
        "pck_sha256": PINNED["members"]["candidate.pck"][1],
        "byte_receipt_verified_at_utc": byte_receipt["verified_at_utc"],
        "historical_byte_receipt_correlated": True,
        "archive_bytes_rehashed_in_this_check": False,
        "store_id_historical_reference_only": "9N95J2T57B41",
        "historical_identity_available": True,
        "historical_identity_rebound_to_sentinel": False,
        "registration_type": "MSIX_OR_PWA_GAME",
        "partner_center_selection": "MSIX or PWA game",
        "identity_capture_structurally_correlated":
            handoff["identity_capture_structurally_correlated"],
        "independent_ui_reference_structurally_compared":
            handoff["identity_fields_compared_to_reference"],
        "official_partner_center_authenticated": False,
        "official_identity_cas": "HOLD",
        "package_version": "HOLD",
        "signed_product_msix": "HOLD",
        "windows_all_auto_intake": "HOLD",
        "product_e2e": "HOLD",
        "local_windows_gate": "DEFERRED_LOCAL_GATE",
        "store_submission_allowed": False,
        "second_3d_product_allowed": False,
        "identity_return_target": "products/prism-route-3d/store/approved-identity.json",
        "next_owner": "36-minute Windows/E2E official UI/CAS lane",
        "required_official_ui_fields": handoff["required_official_ui_fields"],
        "limitations": "Pinned historical real-byte receipt and structural UI checks only; no new live ZIP hash, authenticated Partner Center capture, CAS or Store approval.",
    }


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"),
                      object_pairs_hook=no_duplicate_keys)


def no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key: " + key)
        obj[key] = value
    return obj


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--factory-receipt", default=DEFAULT_FACTORY_RECEIPT)
    parser.add_argument("--provisioner-handoff", default=DEFAULT_PROVISIONER)
    parser.add_argument("--byte-receipt", default=DEFAULT_BYTE_RECEIPT)
    parser.add_argument("--capture")
    parser.add_argument("--comparison-reference")
    parser.add_argument("--live-artifact")
    args = parser.parse_args(argv)
    try:
        result = verify(
            load_json(args.factory_receipt),
            load_json(args.provisioner_handoff),
            load_json(args.byte_receipt),
            load_json(args.capture) if args.capture else None,
            load_json(args.comparison_reference) if args.comparison_reference else None,
            load_json(args.live_artifact) if args.live_artifact else None)
    except (HandoffError, ValueError, OSError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)[:180],
                          "official_identity_cas": "HOLD", "product_e2e": "HOLD",
                          "store_submission_allowed": False}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
