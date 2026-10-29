"""Fail-closed consumption gate for the real Prism Sentinel revision handoff.

This validates snapshot consistency and artifact freshness, NOT authenticated
GitHub bytes, official Partner Center Identity/CAS, signing, or Store readiness.
The consuming Windows lane must independently fetch GitHub run/artifact metadata.
"""
from datetime import datetime, timezone
import re

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PINNED_SENTINEL_SOURCE_SHA = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
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
    if source != PINNED_SENTINEL_SOURCE_SHA:
        raise RevisionHandoffError("unapproved Sentinel source revision")
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


def verify_github_metadata(h, *, fetch_run, fetch_artifacts, now=None):
    """Cross-check the pinned HOLD snapshot against independently fetched GitHub API data.

    Callbacks must be backed by an authenticated GitHub client:
      fetch_run(repository_full_name, run_id) -> workflow-run JSON object
      fetch_artifacts(repository_full_name, run_id) -> list of artifact JSON objects

    This verifies API *metadata*, not ZIP bytes, inner EXE/PCK/MSIX hashes,
    official Store Identity/CAS, signing, or Windows-all-auto acceptance.
    No successful return can authorize a Store submission.
    """
    receipt = validate_revision_handoff(h, now=now, require_unexpired=True)
    if now is None:
        now = datetime.now(timezone.utc)
    now = now.astimezone(timezone.utc)
    expected_repositories = {
        "factory": "shihuiarenjinba-png/3d-game-factory",
        "provisioner_pre": "shihuiarenjinba-png/Repository-Provisioner-3D",
        "unsigned_makeappx": "shihuiarenjinba-png/Repository-Provisioner-3D",
        "independent_pck_diagnostic": "shihuiarenjinba-png/Repository-Provisioner-3D",
    }
    expected_branches = {
        "factory": "codex/prism-route-trap-tension-20261029",
        "provisioner_pre": "codex/e2e-belt-connection-20261027",
        "unsigned_makeappx": "codex/e2e-belt-connection-20261027",
        "independent_pck_diagnostic": "codex/e2e-belt-connection-20261027",
    }
    checked = []
    for kind, repo in expected_repositories.items():
        item = h["evidence"][kind]
        run_id = item["run_id"]
        try:
            run = fetch_run(repo, run_id)
            artifacts = fetch_artifacts(repo, run_id)
        except Exception as exc:
            raise RevisionHandoffError(f"GitHub API unavailable: {kind}") from exc
        if not isinstance(run, dict):
            raise RevisionHandoffError(f"missing GitHub workflow run: {kind}")
        if (type(run.get("id")) is not int or run["id"] != run_id
                or run.get("status") != "completed"
                or run.get("conclusion") != "success"
                or run.get("head_sha") != item["run_head_sha"]
                or run.get("head_branch") != expected_branches[kind]
                or run.get("event") != "push"):
            raise RevisionHandoffError(f"GitHub workflow mismatch: {kind}")
        if not isinstance(artifacts, list):
            raise RevisionHandoffError(f"invalid GitHub artifact list: {kind}")
        matches = [a for a in artifacts
                   if isinstance(a, dict) and type(a.get("id")) is int
                   and a["id"] == item["artifact_id"]]
        if len(matches) != 1:
            raise RevisionHandoffError(f"GitHub artifact missing/duplicate: {kind}")
        artifact = matches[0]
        if (artifact.get("name") != item["artifact_name"]
                or type(artifact.get("size_in_bytes")) is not int
                or artifact["size_in_bytes"] != item["archive_bytes"]
                or artifact.get("digest") != item["archive_digest"]
                or artifact.get("expired") is not False):
            raise RevisionHandoffError(f"GitHub artifact metadata mismatch: {kind}")
        expires = timestamp(artifact.get("expires_at"), f"{kind}.github_expires_at")
        if expires != timestamp(item["expires_at"], f"{kind}.snapshot_expires_at") or expires <= now:
            raise RevisionHandoffError(f"GitHub artifact expired/expiry drift: {kind}")
        provenance = artifact.get("workflow_run")
        if (not isinstance(provenance, dict)
                or type(provenance.get("id")) is not int
                or provenance["id"] != run_id
                or provenance.get("head_sha") != item["run_head_sha"]
                or provenance.get("head_branch") != expected_branches[kind]
                or type(provenance.get("repository_id")) is not int
                or provenance["repository_id"] <= 0
                or provenance.get("head_repository_id") != provenance["repository_id"]):
            raise RevisionHandoffError(f"GitHub artifact provenance mismatch: {kind}")
        checked.append(kind)
    return {
        **receipt,
        "status": "GITHUB_METADATA_MATCH_HOLD_PAYLOAD_NOT_VERIFIED",
        "github_metadata_checked": checked,
        "artifact_zip_bytes_verified": False,
        "inner_exe_pck_msix_verified": False,
        "official_identity_cas_verified": False,
        "store_submission_allowed": False,
    }
