"""Fail-closed validation for the single Prism Route 3D Partner Center handoff.

This validates a machine-readable *claim*, not the external Partner Center
account or a CAS receipt. No Identity, product creation, or Store side effects.
"""
from __future__ import annotations

import re
from typing import Any

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_FIELDS = (
    "store_id", "reserved_display_name", "package_identity_name",
    "publisher", "publisher_display_name", "pfn", "package_sid",
)


class HandoffContractError(ValueError):
    """The 3D handoff is unsafe or internally inconsistent."""


def validate_prism_handoff(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise HandoffContractError("handoff must be an object")
    expected = {
        "schema_version": "1.0",
        "handoff_type": "GAME_3D_PARTNER_CENTER_PRODUCT_CREATION",
        "lane": "GAME_3D",
        "product": "Prism Route 3D",
        "slug": "prism-route-3d",
        "request_id": "3d-prism-route-3d-15fdcb52e46e",
        "source_repository": "shihuiarenjinba-png/3d-game-factory",
        "source_branch": "codex/3d-canary-prism-route-20261028",
        "source_sha": "15fdcb52e46e35e6de8e87c55af99719c21e09b9",
        "registration_type": "MSIX_OR_PWA_GAME",
        "partner_center_selection": "MSIX or PWA game",
        "pre_identity_status": "PRE_IDENTITY_READY",
        "identity_return_target": "products/prism-route-3d/store/approved-identity.json",
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise HandoffContractError(f"pinned handoff mismatch: {key}")
    for key in ("source_sha", "factory_build_head", "observed_factory_branch_head"):
        if not isinstance(data.get(key), str) or not _SHA40.fullmatch(data[key]):
            raise HandoffContractError(f"missing or invalid independently recorded {key}")
    # Validate consistency of the independently observed GitHub objects,
    # not merely their SHA syntax. These values are pinned to this one Canary.
    if data["factory_build_head"] != data["source_sha"]:
        raise HandoffContractError("Factory run head differs from pinned source")
    if data["observed_factory_branch_head"] == data["source_sha"]:
        raise HandoffContractError("expected observed Identity-only branch drift")
    if data.get("identity_return_commit_observed") != data["observed_factory_branch_head"]:
        raise HandoffContractError("Identity return commit differs from observed branch HEAD")
    factory = data.get("factory_export_evidence")
    if not isinstance(factory, dict) or (
        factory.get("run_id") != 40640951915
        or factory.get("artifact_id") != 12795476435
        or factory.get("artifact_name") != "godot-3d-factory-export-evidence"
        or factory.get("authenticated_download_verified") is not True
    ):
        raise HandoffContractError("pinned Factory export evidence mismatch")
    for key in ("provisioner_pre_identity_evidence", "real_makeappx_qa_evidence"):
        evidence = data.get(key)
        if not isinstance(evidence, dict) or any(
            type(evidence.get(field)) is not int or evidence[field] <= 0
            for field in ("run_id", "artifact_id")
        ):
            raise HandoffContractError(f"missing execution evidence: {key}")
    qa = data["real_makeappx_qa_evidence"]
    if qa.get("qa_only") is not True or qa.get("signed") is not False or qa.get("store_ready") is not False:
        raise HandoffContractError("unsigned MakeAppx QA cannot be promoted to Store")
    if data.get("partner_center_product_status") != "EXISTS_MANUAL_CONFIRMED":
        raise HandoffContractError("manual existing product must not be reclassified as not created")
    if data.get("allow_local_product_creation") is not False:
        raise HandoffContractError("duplicate Partner Center product creation forbidden")
    if data.get("identity_status") != "MANUAL_REFERENCE_OBSERVED__OFFICIAL_CAPTURE_NOT_PROVEN":
        raise HandoffContractError("manual reference is not authenticated Identity")
    if data.get("identity_return_file_status") != "EXISTS_UNVERIFIED__NO_CAS_RECEIPT":
        raise HandoffContractError("Identity file presence is not CAS proof")
    if data.get("identity_return_cas_receipt_status") != "NOT_PROVEN":
        raise HandoffContractError("CAS receipt not established")
    for key in ("identity_return_commit_observed", "identity_return_file_blob_sha_observed"):
        if not isinstance(data.get(key), str) or not _SHA40.fullmatch(data[key]):
            raise HandoffContractError(f"missing observed Git object: {key}")
    for key in ("local_operator_identity_capture", "github_to_local_trigger"):
        if data.get(key) != "NOT_PROVEN":
            raise HandoffContractError(f"unverified local gate: {key}")
    if data.get("post_identity_status") != "HOLD":
        raise HandoffContractError("post-Identity package cannot be ready yet")
    post = data.get("post_identity_package_gate")
    if not isinstance(post, dict) or set(post) != {
        "version_status", "approved_version", "candidate_manifest_version",
        "candidate_msix_sha256", "pre_identity_exe_sha256_kind",
        "identity_cas_receipt", "version_approval_receipt",
        "signature_verification_receipt", "msix_safety_qa_receipt",
        "intake_status",
    }:
        raise HandoffContractError("missing explicit post-Identity package gate")
    if post["version_status"] != "HOLD_NO_APPROVED_POST_IDENTITY_VERSION":
        raise HandoffContractError("post-Identity version is not approved")
    if post["pre_identity_exe_sha256_kind"] != "EXE_ONLY_NOT_MSIX":
        raise HandoffContractError("pre-Identity EXE digest cannot be an MSIX digest")
    if post["intake_status"] != "HOLD_PRE_MSIX":
        raise HandoffContractError("post-Identity MSIX intake not authorized")
    for key in ("approved_version", "candidate_manifest_version", "candidate_msix_sha256",
                "identity_cas_receipt", "version_approval_receipt",
                "signature_verification_receipt", "msix_safety_qa_receipt"):
        if post[key] is not None:
            raise HandoffContractError(f"unverified post-Identity evidence: {key}")
    fields = data.get("identity_fields_required")
    if not isinstance(fields, dict) or set(fields) != set(_FIELDS) or any(v is not None for v in fields.values()):
        raise HandoffContractError("unverified official Identity fields must remain unresolved")
    controls = data.get("controls")
    if not isinstance(controls, dict):
        raise HandoffContractError("missing controls")
    for key in ("second_3d_product_allowed", "store_submission_allowed", "identity_guessing_allowed"):
        if controls.get(key) is not False:
            raise HandoffContractError(f"unsafe permission: {key}")
    for key in ("main_release_write_allowed", "force_push_allowed", "auto_merge_allowed"):
        if controls.get(key) is not False:
            raise HandoffContractError(f"unsafe repository write permission: {key}")
    if controls.get("local_gpu_install_gui") != "DEFERRED_LOCAL_GATE":
        raise HandoffContractError("physical Windows QA is not proven")
    if controls.get("windows_all_auto_intake_status") != "HOLD":
        raise HandoffContractError("no post-Identity Windows intake receipt")
