"""Fail-closed consumption gate for the real Prism Sentinel revision handoff.

This validates snapshot consistency and artifact freshness, NOT authenticated
GitHub bytes, official Partner Center Identity/CAS, signing, or Store readiness.
The consuming Windows lane must independently fetch GitHub run/artifact metadata.
"""
from datetime import datetime, timezone
import re

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ARTIFACTS = {
    "factory": "godot-3d-factory-export-evidence",
    "provisioner_pre": "prism-route-3d-sentinel-revision-provisioner-pre",
    "unsigned_makeappx": "prism-route-3d-sentinel-revision-makeappx-unsigned-qa",
    "independent_pck_diagnostic": "prism-route-3d-independent-pck-diagnostic",
}


class RevisionHandoffError(ValueError):
    """Snapshot cannot safely be consumed."""


def timestamp(value, field):
    if not isinstance(value, str):
        raise RevisionHandoffError(f"missing {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RevisionHandoffError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RevisionHandoffError(f"naive {field}")
    return parsed.astimezone(timezone.utc)


def validate_revision_handoff(h, *, now=None, require_unexpired=True):
    """Return HOLD-only receipt. Set require_unexpired for artifact consumption."""
    if not isinstance(h, dict):
        raise RevisionHandoffError("handoff is not an object")
    source = h.get("source_sha")
    if not isinstance(source, str) or not SHA.fullmatch(source):
        raise RevisionHandoffError("invalid source_sha")
    expected = {
        "product": "Prism Route 3D",
        "slug": "prism-route-3d",
        "source_repository": "shihuiarenjinba-png/3d-game-factory",
        "source_branch": "codex/prism-route-trap-tension-20261029",
        "request_id": "3d-prism-route-3d-" + source[:12],
        "packaging_strategy": "GODOT_WINDOWS_EXE_PCK_TO_MAKEAPPX_STANDARD_MSIX",
        "registration_type": "MSIX_OR_PWA_GAME",
        "partner_center_selection": "MSIX or PWA game",
        "partner_center_product_status": "UNRECONCILED_MANUAL_OBSERVATIONS",
        "identity_status": "OFFICIAL_CAPTURE_AND_NEW_REVISION_CAS_NOT_PROVEN",
        "identity_rebinding_status": "HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING",
        "identity_return_target": "products/prism-route-3d/store/approved-identity.json",
    }
    for key, value in expected.items():
        if h.get(key) != value:
            raise RevisionHandoffError(f"unsafe {key}")
    if h.get("allow_local_product_creation") is not False:
        raise RevisionHandoffError("duplicate Partner Center product creation")
    old = h.get("immutable_original_provenance")
    if not isinstance(old, dict) or old.get("source_sha") != "15fdcb52e46e35e6de8e87c55af99719c21e09b9" or old.get("identity_reference_is_new_revision_approval") is not False or old["source_sha"] == source:
        raise RevisionHandoffError("historical Identity cannot authorize revision")
    request = h.get("user_id_request")
    fields = {"store_id", "reserved_display_name", "package_identity_name", "publisher",
              "publisher_display_name", "pfn", "package_sid"}
    if not isinstance(request, dict) or request.get("status") != "REVERIFY_EXISTING_PRODUCT_IDENTITY" or request.get("xbox_fields_required") is not False or not isinstance(request.get("required_fields"), list) or set(request["required_fields"]) != fields:
        raise RevisionHandoffError("missing official Identity request")
    observed = timestamp(h.get("evidence_observed_at"), "evidence_observed_at")
    if now is None:
        now = datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise RevisionHandoffError("now must be timezone aware")
    now = now.astimezone(timezone.utc)
    if observed > now:
        raise RevisionHandoffError("future observation")
    evidence = h.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(ARTIFACTS):
        raise RevisionHandoffError("missing evidence artifacts")
    ids = set()
    for key, expected_name in ARTIFACTS.items():
        item = evidence[key]
        if not isinstance(item, dict) or item.get("artifact_name") != expected_name:
            raise RevisionHandoffError(f"wrong artifact kind: {key}")
        for field in ("run_id", "artifact_id", "archive_bytes"):
            if type(item.get(field)) is not int or item[field] <= 0:
                raise RevisionHandoffError(f"invalid {key}.{field}")
        if item["artifact_id"] in ids:
            raise RevisionHandoffError("duplicate artifact ID")
        ids.add(item["artifact_id"])
        head, digest = item.get("run_head_sha"), item.get("archive_digest")
        if not isinstance(head, str) or not SHA.fullmatch(head):
            raise RevisionHandoffError(f"invalid run HEAD: {key}")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise RevisionHandoffError(f"invalid archive digest: {key}")
        expires = timestamp(item.get("expires_at"), f"{key}.expires_at")
        if expires <= observed or (require_unexpired and expires <= now):
            raise RevisionHandoffError(f"expired artifact: {key}")
    if evidence["factory"]["run_head_sha"] != source:
        raise RevisionHandoffError("Factory source mismatch")
    if evidence["provisioner_pre"]["run_head_sha"] != evidence["unsigned_makeappx"]["run_head_sha"]:
        raise RevisionHandoffError("PRE/MakeAppx run HEAD mismatch")
    if evidence["provisioner_pre"]["run_head_sha"] == source:
        raise RevisionHandoffError("Provisioner HEAD masquerades as Factory source")
    qa = evidence["unsigned_makeappx"]
    if qa.get("signed") is not False or qa.get("store_ready") is not False:
        raise RevisionHandoffError("unsigned QA promoted")
    pck = evidence["independent_pck_diagnostic"]
    if pck.get("diagnostic_only") is not True or pck.get("not_store_payload") is not True:
        raise RevisionHandoffError("diagnostic promoted")
    gates = h.get("gates")
    if not isinstance(gates, dict) or any(gates.get(key) != "HOLD" for key in (
        "identity_cas", "approved_package_version", "signed_post_identity_msix",
        "windows_all_auto_intake", "product_e2e")):
        raise RevisionHandoffError("unproven E2E gate promoted")
    if gates.get("local_gpu_install_gui") != "DEFERRED_LOCAL_GATE" or gates.get("unsigned_makeappx") != "PASS_UNSIGNED_QA_ONLY":
        raise RevisionHandoffError("local/unsigned gate misrepresented")
    controls = h.get("controls")
    if not isinstance(controls, dict) or any(controls.get(key) is not False for key in (
        "second_3d_product_allowed", "store_submission_allowed", "main_release_write_allowed",
        "force_push_allowed", "auto_merge_allowed")):
        raise RevisionHandoffError("unsafe write control")
    return {"status": "CONTRACT_VALID_HOLD_NOT_AUTHENTICATED",
            "source_sha": source, "request_id": expected["request_id"],
            "identity_cas": "HOLD", "signed_msix": "HOLD",
            "windows_all_auto_intake": "HOLD", "product_e2e": "HOLD",
            "github_artifact_authentication": "REQUIRED_SEPARATELY"}
