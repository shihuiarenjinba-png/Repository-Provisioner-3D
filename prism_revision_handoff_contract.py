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
    if not isinstance(old, dict) or old.get("source_sha") != "15fdcb52e46e35e6de8e87c55af99719c21e09b9" or old.get("identity_reference_is_new_revision_approval") is not False or old.get("identity_reference_commit") != "11417b75636ee18816028ffd5221884c4c9a9836" or old["source_sha"] == source:
        raise RevisionHandoffError("historical Identity cannot authorize revision")
    request = h.get("user_id_request")
    fields = {"store_id", "reserved_display_name", "package_identity_name", "publisher",
              "publisher_display_name", "pfn", "package_sid"}
    if not isinstance(request, dict) or request.get("status") != "REVERIFY_EXISTING_PRODUCT_IDENTITY" or request.get("xbox_fields_required") is not False or not isinstance(request.get("required_fields"), list) or len(request["required_fields"]) != len(fields) or set(request["required_fields"]) != fields:
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
    # This old-source PCK diagnostic is archival provenance, not the Sentinel
    # payload. Its expiry must not disable live Factory/PRE/MSIX verification.
    historical_diagnostic = "independent_pck_diagnostic"
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
        if expires <= observed or (require_unexpired and expires <= now
                                   and key != historical_diagnostic):
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
    expected_non_e2e_gates = {
        "factory_export": "PASS_PREVIOUS_RUN",
        "godot_windows_export": "PASS_PREVIOUS_RUN",
        "exe_pck_provisioner": "PASS_REAL_REVISION_BYTES_CORRELATED",
        "pre_identity": "PRE_IDENTITY_READY",
        "registration_type": "MSIX_OR_PWA_GAME",
    }
    if any(gates.get(key) != value for key, value in expected_non_e2e_gates.items()):
        raise RevisionHandoffError("unproven PRE or registration gate promoted")
    if gates.get("local_gpu_install_gui") != "DEFERRED_LOCAL_GATE" or gates.get("unsigned_makeappx") != "PASS_UNSIGNED_QA_ONLY":
        raise RevisionHandoffError("local/unsigned gate misrepresented")
    # A verifier SUCCESS claim must refer to exactly the artifacts pinned
    # above. This is an internal consistency check, NOT proof that the
    # referenced GitHub job/step actually ran: consumers must authenticate it.
    verification = h.get("pinned_snapshot_verification")
    if not isinstance(verification, dict):
        raise RevisionHandoffError("missing pinned verifier receipt")
    if verification.get("status") != "PASS_REAL_ZIP_EXE_PCK_MSIX_BYTES_HOLD_ONLY":
        raise RevisionHandoffError("unsafe pinned verifier status")
    for field in ("verified_workflow_run_id", "verified_job_id"):
        if type(verification.get(field)) is not int or verification[field] <= 0:
            raise RevisionHandoffError(f"invalid pinned verifier {field}")
    verifier_head = verification.get("verified_workflow_head_sha")
    if not isinstance(verifier_head, str) or not SHA.fullmatch(verifier_head):
        raise RevisionHandoffError("invalid pinned verifier HEAD")
    if (verification.get("verified_step")
            != "Authenticated real Factory and unsigned MSIX byte verification (HOLD-only)"
            or verification.get("verified_step_conclusion") != "success"):
        raise RevisionHandoffError("pinned verifier step not successful")
    verified_ids = verification.get("verified_artifact_ids")
    if (not isinstance(verified_ids, dict) or set(verified_ids) != set(ARTIFACTS)
            or any(type(verified_ids[kind]) is not int
                   or verified_ids[kind] != evidence[kind]["artifact_id"]
                   for kind in ARTIFACTS)):
        raise RevisionHandoffError("pinned verifier artifact IDs do not match snapshot")
    for field in ("new_output_artifact_bytes_reverified",
                  "official_identity_cas_verified", "store_submission_allowed"):
        if verification.get(field) is not False:
            raise RevisionHandoffError(f"unsafe pinned verifier {field}")
    if not isinstance(verification.get("verification_scope"), str) or not verification["verification_scope"].strip():
        raise RevisionHandoffError("missing pinned verifier scope")
    controls = h.get("controls")
    if not isinstance(controls, dict) or any(controls.get(key) is not False for key in (
        "second_3d_product_allowed", "store_submission_allowed", "main_release_write_allowed",
        "force_push_allowed", "auto_merge_allowed")):
        raise RevisionHandoffError("unsafe write control")
    return {"status": "CONTRACT_VALID_HOLD_NOT_AUTHENTICATED",
            "source_sha": source, "request_id": expected["request_id"],
            "identity_cas": "HOLD", "signed_msix": "HOLD",
            "windows_all_auto_intake": "HOLD", "product_e2e": "HOLD",
            "github_artifact_authentication": "REQUIRED_SEPARATELY",
            "pinned_verifier_claim": "CONSISTENT_NOT_INDEPENDENTLY_AUTHENTICATED",
            "historical_pck_diagnostic_expired": (
                timestamp(evidence[historical_diagnostic]["expires_at"],
                          "historical_pck_diagnostic.expires_at") <= now),
            "historical_pck_diagnostic_is_new_source_payload": False}


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
    expected_repository_ids = {
        "factory": 1434223918,
        "provisioner_pre": 1434261585,
        "unsigned_makeappx": 1434261585,
        "independent_pck_diagnostic": 1434261585,
    }
    expected_branches = {
        "factory": "codex/prism-route-trap-tension-20261029",
        "provisioner_pre": "codex/e2e-belt-connection-20261027",
        "unsigned_makeappx": "codex/e2e-belt-connection-20261027",
        "independent_pck_diagnostic": "codex/e2e-belt-connection-20261027",
    }
    expected_workflows = {
        "factory": (".github/workflows/prism-route-canary-export.yml", 399058278),
        "provisioner_pre": (".github/workflows/prism-revision-provisioner.yml", 400477810),
        "unsigned_makeappx": (".github/workflows/prism-revision-makeappx.yml", 400479598),
        "independent_pck_diagnostic": (".github/workflows/canary-live-provenance.yml", 399059609),
    }
    checked = []
    skipped_historical = []
    for kind, repo in expected_repositories.items():
        if (kind == "independent_pck_diagnostic"
                and timestamp(h["evidence"][kind]["expires_at"],
                              "historical_diagnostic.expires_at") <= now):
            # Expired legacy-source diagnostic: never fetch/claim it as live
            # evidence. All three Sentinel-relevant artifacts remain required.
            skipped_historical.append(kind)
            continue
        item = h["evidence"][kind]
        run_id = item["run_id"]
        repository_id = expected_repository_ids[kind]
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
                or run.get("event") != "push"
                or run.get("path") != expected_workflows[kind][0]
                or type(run.get("workflow_id")) is not int
                or run["workflow_id"] != expected_workflows[kind][1]
                or not isinstance(run.get("repository"), dict)
                or type(run["repository"].get("id")) is not int
                or run["repository"]["id"] != repository_id
                or not isinstance(run.get("head_repository"), dict)
                or type(run["head_repository"].get("id")) is not int
                or run["head_repository"]["id"] != repository_id):
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
                or provenance["repository_id"] != repository_id
                or type(provenance.get("head_repository_id")) is not int
                or provenance["head_repository_id"] != repository_id):
            raise RevisionHandoffError(f"GitHub artifact provenance mismatch: {kind}")
        checked.append(kind)
    return {
        **receipt,
        "status": "GITHUB_METADATA_MATCH_HOLD_PAYLOAD_NOT_VERIFIED",
        "github_metadata_checked": checked,
        "expired_historical_diagnostics_skipped": skipped_historical,
        "artifact_zip_bytes_verified": False,
        "inner_exe_pck_msix_verified": False,
        "official_identity_cas_verified": False,
        "store_submission_allowed": False,
    }
