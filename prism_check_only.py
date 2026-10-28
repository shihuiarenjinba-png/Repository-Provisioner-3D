"""Read-only Prism Route 3D check-only handoff for the 36-minute Windows lane.

This validates the pinned local contract and compares *caller-supplied*
observations. It does not authenticate GitHub, Partner Center, CAS, signatures,
or Windows intake; no network calls, writes, or Store actions occur.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Any

from partner_center_handoff_contract import HandoffContractError, validate_prism_handoff

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_PATH = "products/prism-route-3d/store/approved-identity.json"
_ALLOWED = {
    "factory_run_id", "factory_artifact_id", "factory_run_head",
    "factory_branch_head", "identity_file_blob_sha",
    "identity_only_compare", "pre_identity_exe_sha256",
    "pre_identity_pck_sha256", "unsigned_qa_msix_sha256",
}


def _sha(value: Any, key: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise HandoffContractError(f"invalid {key}")


def _match(value: Any, expected: Any, key: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise HandoffContractError(f"conflicting independent observation: {key}")


def prism_check_only(handoff: dict[str, Any],
                     observations: dict[str, Any] | None = None,
                     *, now_utc: datetime | None = None) -> dict[str, Any]:
    """Return a machine-readable HOLD receipt; never authorize post-Identity intake."""
    validate_prism_handoff(handoff)
    if observations is None:
        observations = {}
    if not isinstance(observations, dict) or set(observations) - _ALLOWED:
        raise HandoffContractError("unexpected observation field or invalid observations")
    expected = {
        "factory_run_id": handoff["factory_export_evidence"]["run_id"],
        "factory_artifact_id": handoff["factory_export_evidence"]["artifact_id"],
        "factory_run_head": handoff["source_sha"],
        "factory_branch_head": handoff["observed_factory_branch_head"],
        "identity_file_blob_sha": handoff["identity_return_file_blob_sha_observed"],
    }
    for key, value in expected.items():
        if key in observations:
            _match(observations[key], value, key)
    if "identity_only_compare" in observations:
        compare = observations["identity_only_compare"]
        if not isinstance(compare, dict) or set(compare) != {
            "status", "ahead_by", "behind_by", "changed_files"
        }:
            raise HandoffContractError("invalid identity-only compare evidence")
        _match(compare["status"], "ahead", "compare status")
        _match(compare["ahead_by"], 1, "compare ahead_by")
        _match(compare["behind_by"], 0, "compare behind_by")
        _match(compare["changed_files"], [_IDENTITY_PATH], "compare changed_files")
    for key in ("pre_identity_exe_sha256", "pre_identity_pck_sha256",
                "unsigned_qa_msix_sha256"):
        if key in observations:
            _sha(observations[key], key, _SHA256)
    # The handoff is a historical snapshot. A recorded "not expired" flag
    # is not proof that the artifact is still retrievable at check time.
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    if now_utc.tzinfo is None or now_utc.utcoffset() is None:
        raise HandoffContractError("now_utc must be timezone-aware")
    now_utc = now_utc.astimezone(timezone.utc)
    freshness = {}
    for role, field in (
        ("factory_export", "factory_export_evidence"),
        ("provisioner_pre_identity", "provisioner_pre_identity_evidence"),
        ("unsigned_makeappx_qa", "real_makeappx_qa_evidence"),
    ):
        expires_at = handoff[field].get("artifact_expires_at")
        if not expires_at:
            freshness[role] = "UNKNOWN_NO_EXPIRY_IN_SNAPSHOT"
            continue
        try:
            expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc)
        except (ValueError, TypeError) as exc:
            raise HandoffContractError(f"invalid artifact expiry: {field}") from exc
        freshness[role] = (
            "EXPIRED_REQUIRES_REMOTE_REFRESH" if now_utc >= expiry
            else "NOT_EXPIRED_BY_SNAPSHOT_TIME_ONLY"
        )
    # Pinned identifiers are compared for equality. Payload digests have
    # no trusted reference in this handoff: syntax checks are NOT matches.
    format_only = {
        "pre_identity_exe_sha256", "pre_identity_pck_sha256",
        "unsigned_qa_msix_sha256",
    }
    checks = {
        key: ("NOT_SUPPLIED" if key not in observations
              else "FORMAT_ONLY_CALLER_SUPPLIED_NOT_AUTHENTICATED"
              if key in format_only
              else "MATCHED_CALLER_SUPPLIED_NOT_AUTHENTICATED")
        for key in sorted(_ALLOWED)
    }
    return {
        "schema_version": "1.0",
        "mode": "CHECK_ONLY_NO_SIDE_EFFECTS",
        "lane": "GAME_3D",
        "product": handoff["product"],
        "slug": handoff["slug"],
        "request_id": handoff["request_id"],
        "source_branch": handoff["source_branch"],
        "immutable_source_sha": handoff["source_sha"],
        "factory_build_head": handoff["factory_build_head"],
        "identity_only_descendant_head": handoff["observed_factory_branch_head"],
        "identity_return_target": handoff["identity_return_target"],
        "registration_type": handoff["registration_type"],
        "partner_center_selection": handoff["partner_center_selection"],
        "partner_center_product_status": "EXISTS_MANUAL_CONFIRMED",
        "pre_identity_status": "PRE_IDENTITY_READY",
        "identity_status": "OFFICIAL_CAPTURE_AND_REQUEST_CAS_NOT_PROVEN",
        "observations": checks,
        "artifact_snapshot_freshness": {
            "evaluated_at_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "roles": freshness,
            "current_remote_head_verified": False,
            "remote_artifact_retrieval_verified": False,
        },
        "digest_roles": {
            "pre_identity_exe_sha256": observations.get("pre_identity_exe_sha256"),
            "pre_identity_pck_sha256": observations.get("pre_identity_pck_sha256"),
            "unsigned_qa_msix_sha256": observations.get("unsigned_qa_msix_sha256"),
            "final_signed_msix_sha256": None,
            "package_sha256": None,
        },
        "post_identity_package_gate": {
            "approved_four_part_version": None,
            "request_specific_identity_cas_receipt": None,
            "version_approval_receipt": None,
            "signature_verification_receipt": None,
            "msix_safety_qa_receipt": None,
            "post_identity_ready": False,
            "windows_all_auto_intake_allowed": False,
            "store_ready": False,
            "intake_status": "HOLD_NO_AUTHENTICATED_IDENTITY_APPROVED_SIGNED_MSIX",
        },
        "local_windows_gate": "DEFERRED_LOCAL_GATE",
        "product_e2e": "HOLD",
        "provenance_limitation": (
            "Caller-supplied observations are compared against pinned records only. "
            "This check does not independently authenticate remote GitHub or "
            "Partner Center, approve CAS/version, inspect signed MSIX, or prove intake."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, default=(
        Path(__file__).resolve().parent / "handoffs" /
        "prism-route-3d-partner-center-product-creation.json"
    ))
    parser.add_argument("--observations", type=Path, help="Optional read-only JSON observations")
    args = parser.parse_args()
    try:
        for path in (args.handoff, args.observations):
            if path is not None and (not path.is_file() or path.stat().st_size > 65536):
                raise HandoffContractError("missing or oversized JSON input")
        handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
        observations = (json.loads(args.observations.read_text(encoding="utf-8"))
                        if args.observations else None)
        result = prism_check_only(handoff, observations)
    except (HandoffContractError, ValueError, OSError, UnicodeError) as exc:
        print(json.dumps({"mode": "CHECK_ONLY_NO_SIDE_EFFECTS",
                          "status": "HOLD_INVALID_EVIDENCE",
                          "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
