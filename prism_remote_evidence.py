"""Fail-closed comparison of GitHub Actions API observations for pinned Prism Canary.

The caller must obtain each JSON file using authenticated `gh api` in the
GitHub Actions job. This module itself does not authenticate network data,
download ZIP bytes, validate Partner Center Identity, or authorize Store intake.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from partner_center_handoff_contract import HandoffContractError, validate_prism_handoff

FACTORY_REPO = "shihuiarenjinba-png/3d-game-factory"
PROVISIONER_REPO = "shihuiarenjinba-png/Repository-Provisioner-3D"
FACTORY_BRANCH = "codex/3d-canary-prism-route-20261028"
PROVISIONER_BRANCH = "codex/e2e-belt-connection-20261027"
IDENTITY_PATH = "products/prism-route-3d/store/approved-identity.json"


def _eq(actual: Any, expected: Any, description: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise HandoffContractError(f"remote snapshot mismatch: {description}")


def _expiry(value: Any, now: datetime) -> None:
    if not isinstance(value, str):
        raise HandoffContractError("missing remote artifact expiry")
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HandoffContractError("invalid remote artifact expiry") from exc
    if dt <= now:
        raise HandoffContractError("remote artifact expired")


def _check_run(run: dict[str, Any], evidence: dict[str, Any], branch: str,
               head: str) -> None:
    _eq(run.get("id"), evidence["run_id"], "run id")
    _eq(run.get("head_sha"), head, "run HEAD")
    _eq(run.get("head_branch"), branch, "run branch")
    _eq(run.get("status"), "completed", "run status")
    _eq(run.get("conclusion"), "success", "run conclusion")


def _check_artifact(artifact: dict[str, Any], evidence: dict[str, Any],
                    head: str, branch: str, now: datetime) -> None:
    _eq(artifact.get("id"), evidence["artifact_id"], "artifact id")
    _eq(artifact.get("name"), evidence["artifact_name"], "artifact name")
    _eq(artifact.get("expired"), False, "artifact expired flag")
    _eq(artifact.get("size_in_bytes"), evidence["artifact_archive_size_bytes"],
        "artifact archive size")
    _eq(artifact.get("digest"), evidence["artifact_archive_digest"],
        "artifact ZIP digest")
    _eq(artifact.get("expires_at"), evidence["artifact_expires_at"],
        "artifact expiration metadata")
    _expiry(artifact["expires_at"], now)
    provenance = artifact.get("workflow_run")
    if not isinstance(provenance, dict):
        raise HandoffContractError("missing artifact workflow_run provenance")
    _eq(provenance.get("id"), evidence["run_id"], "artifact parent run")
    _eq(provenance.get("head_sha"), head, "artifact parent HEAD")
    _eq(provenance.get("head_branch"), branch, "artifact parent branch")


def verify_remote_snapshot(handoff: dict[str, Any], remote: dict[str, Any],
                           *, now_utc: datetime | None = None) -> dict[str, Any]:
    validate_prism_handoff(handoff)
    if not isinstance(remote, dict) or set(remote) != {
        "factory_run", "factory_artifact", "pre_run", "pre_artifact",
        "qa_run", "qa_artifact", "pck_artifact", "factory_compare",
        "factory_branch"
    } or not all(isinstance(v, dict) for v in remote.values()):
        raise HandoffContractError("missing remote GitHub API observations")
    now = now_utc or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise HandoffContractError("now_utc must be timezone-aware")
    now = now.astimezone(timezone.utc)
    factory = handoff["factory_export_evidence"]
    pre = handoff["provisioner_pre_identity_evidence"]
    qa = handoff["real_makeappx_qa_evidence"]
    pck = handoff["independent_pck_diagnostic_evidence"]
    _check_run(remote["factory_run"], factory, FACTORY_BRANCH, handoff["source_sha"])
    _check_artifact(remote["factory_artifact"], factory, handoff["source_sha"],
                    FACTORY_BRANCH, now)
    for run_key, artifact_key, evidence in (
        ("pre_run", "pre_artifact", pre), ("qa_run", "qa_artifact", qa)
    ):
        _check_run(remote[run_key], evidence, PROVISIONER_BRANCH,
                   evidence["run_head_sha"])
        _check_artifact(remote[artifact_key], evidence, evidence["run_head_sha"],
                        PROVISIONER_BRANCH, now)
    _eq(pck["run_id"], pre["run_id"], "PCK parent PRE run")
    _eq(pck["run_head_sha"], pre["run_head_sha"], "PCK parent HEAD")
    _check_artifact(remote["pck_artifact"], pck, pre["run_head_sha"],
                    PROVISIONER_BRANCH, now)
    # A valid historical Identity-only compare does not prove that the
    # current Factory branch still points to the same observed commit.
    branch_snapshot = remote["factory_branch"]
    _eq(branch_snapshot.get("name"), FACTORY_BRANCH, "current Factory branch name")
    branch_commit = branch_snapshot.get("commit")
    if not isinstance(branch_commit, dict):
        raise HandoffContractError("missing current Factory branch commit")
    _eq(branch_commit.get("sha"), handoff["observed_factory_branch_head"],
        "current Factory branch HEAD")
    compare = remote["factory_compare"]
    _eq(compare.get("status"), "ahead", "identity-only compare status")
    _eq(compare.get("ahead_by"), 1, "identity-only compare ahead")
    _eq(compare.get("behind_by"), 0, "identity-only compare behind")
    files = compare.get("files")
    if not isinstance(files, list):
        raise HandoffContractError("missing compare changed files")
    _eq([f.get("filename") for f in files if isinstance(f, dict)],
        [IDENTITY_PATH], "identity-only changed file")
    _eq(compare.get("base_commit", {}).get("sha"), handoff["source_sha"],
        "compare base commit")
    _eq(compare.get("merge_base_commit", {}).get("sha"), handoff["source_sha"],
        "compare merge base")
    _eq(compare.get("total_commits"), 1, "identity-only commit count")
    commits = compare.get("commits")
    if not isinstance(commits, list) or len(commits) != 1 or not isinstance(commits[0], dict):
        raise HandoffContractError("missing single Identity-only commit")
    _eq(commits[0].get("sha"), handoff["observed_factory_branch_head"],
        "compare head commit")
    if len(files) != 1 or not isinstance(files[0], dict):
        raise HandoffContractError("missing Identity-only changed file")
    _eq(files[0].get("status"), "added", "Identity-only file status")
    _eq(files[0].get("previous_filename"), None, "Identity-only previous path")
    return {
        "schema_version": "1.0",
        "mode": "GITHUB_API_METADATA_COMPARISON_ONLY",
        "request_id": handoff["request_id"],
        "immutable_source_sha": handoff["source_sha"],
        "pre_identity_status": "PRE_IDENTITY_READY",
        "factory_run_id": factory["run_id"],
        "pre_run_id": pre["run_id"],
        "qa_run_id": qa["run_id"],
        "pck_diagnostic_artifact_id": pck["artifact_id"],
        "pck_payload_bytes_verified_by_this_check": False,
        "metadata_comparison": "PASS_CALLER_SUPPLIED_API_RESPONSES",
        "factory_branch_head_matched_snapshot": True,
        "zip_bytes_verified_by_this_check": False,
        "partner_center_identity_verified": False,
        "cas_receipt_verified": False,
        "signed_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD",
        "local_gate": "DEFERRED_LOCAL_GATE",
        "limitation": "Use authenticated gh api to supply the observations. This "
                      "function compares API metadata, not downloaded ZIP bytes, "
                      "Partner Center Identity, signed packages, or Windows intake.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--remote", type=Path, required=True)
    args = parser.parse_args()
    try:
        for path in (args.handoff, args.remote):
            if not path.is_file() or path.stat().st_size > 2_000_000:
                raise HandoffContractError("missing or oversized input")
        handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
        remote = json.loads(args.remote.read_text(encoding="utf-8"))
        result = verify_remote_snapshot(handoff, remote)
    except (HandoffContractError, OSError, ValueError, UnicodeError) as exc:
        print(json.dumps({"status": "HOLD_REMOTE_EVIDENCE_MISMATCH",
                          "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
