"""Fail-closed freshness check for pinned Prism Sentinel GitHub artifact metadata.

Validates a supplied REST metadata snapshot against independently audited
anchors. It does NOT authenticate the snapshot, download ZIPs, validate
Partner Center Identity, sign packages, or authorize Windows/Store intake.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from prism_20261101_source_gate import ANCHORS, SENTINEL, SENTINEL_REQUEST

ROLES = ("factory", "sentinel_pre", "sentinel_unsigned_qa")
# Provenance from authenticated GitHub REST artifact metadata. The Factory
# workflow HEAD is the game source; Provisioner workflow HEAD is the builder
# commit and must NOT be mistaken for the game source SHA.
WORKFLOW_PROVENANCE = {
    "factory": (
        "godot-3d-factory-export-evidence", 1434223918,
        "codex/prism-route-trap-tension-20261029", SENTINEL,
    ),
    "sentinel_pre": (
        "prism-route-3d-sentinel-revision-provisioner-pre", 1434261585,
        "codex/e2e-belt-connection-20261027",
        "0bfecf99fb92ce1f05fb15b81760909eb699444b",
    ),
    "sentinel_unsigned_qa": (
        "prism-route-3d-sentinel-revision-makeappx-unsigned-qa", 1434261585,
        "codex/e2e-belt-connection-20261027",
        "0bfecf99fb92ce1f05fb15b81760909eb699444b",
    ),
}


class ArtifactFreshnessError(ValueError):
    pass


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactFreshnessError("duplicate metadata key")
        result[key] = value
    return result


def _timestamp(value):
    if not isinstance(value, str):
        raise ArtifactFreshnessError("missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArtifactFreshnessError("invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ArtifactFreshnessError("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def validate(snapshot, *, now=None):
    if not isinstance(snapshot, dict):
        raise ArtifactFreshnessError("invalid snapshot")
    if (snapshot.get("schema_version") != "1.0" or
            snapshot.get("snapshot_type") != "GAME_3D_GITHUB_ARTIFACT_METADATA" or
            snapshot.get("source_sha") != SENTINEL or
            snapshot.get("request_id") != SENTINEL_REQUEST):
        raise ArtifactFreshnessError("snapshot source/request mismatch")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ArtifactFreshnessError("now must have timezone")
    now = now.astimezone(timezone.utc)
    checked = _timestamp(snapshot.get("checked_at_utc"))
    if checked > now + timedelta(minutes=5) or now - checked > timedelta(minutes=30):
        raise ArtifactFreshnessError("stale or future metadata snapshot")
    artifacts = snapshot.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ROLES):
        raise ArtifactFreshnessError("incomplete or extra artifact roles")
    expirations = {}
    for role in ROLES:
        item = artifacts[role]
        if not isinstance(item, dict):
            raise ArtifactFreshnessError("invalid artifact: " + role)
        artifact_id, run_id, digest, size = ANCHORS[role]
        workflow_run = item.get("workflow_run")
        if (type(item.get("id")) is not int or item["id"] != artifact_id or
                type(item.get("size_in_bytes")) is not int or
                item["size_in_bytes"] != size or
                item.get("digest") != "sha256:" + digest or
                not isinstance(workflow_run, dict) or
                type(workflow_run.get("id")) is not int or
                workflow_run["id"] != run_id):
            raise ArtifactFreshnessError("artifact metadata anchor mismatch: " + role)
        expected_name, repo_id, branch, head_sha = WORKFLOW_PROVENANCE[role]
        if (item.get("name") != expected_name or
                type(workflow_run.get("repository_id")) is not int or
                workflow_run["repository_id"] != repo_id or
                type(workflow_run.get("head_repository_id")) is not int or
                workflow_run["head_repository_id"] != repo_id or
                workflow_run.get("head_branch") != branch or
                workflow_run.get("head_sha") != head_sha):
            raise ArtifactFreshnessError("workflow provenance mismatch: " + role)
        if item.get("expired") is not False:
            raise ArtifactFreshnessError("expired or unknown artifact status: " + role)
        expiry = _timestamp(item.get("expires_at"))
        if expiry <= now + timedelta(minutes=15):
            raise ArtifactFreshnessError("expired or near-expiry artifact: " + role)
        expirations[role] = expiry.isoformat()
    return {
        "status": "HOLD_FRESH_METADATA_MATCHES_PINNED_AUDIT",
        "source_sha": SENTINEL, "request_id": SENTINEL_REQUEST,
        "expires_at_utc": expirations,
        "metadata_live_authenticated_by_this_script": False,
        "zip_bytes_reverified_by_this_script": False,
        "official_identity_cas_verified": False,
        "signed_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD", "store_submission_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.metadata.is_file() or args.metadata.stat().st_size > 65536:
            raise ArtifactFreshnessError("missing or oversized metadata")
        snapshot = json.loads(args.metadata.read_text(encoding="utf-8"),
                              object_pairs_hook=_no_duplicate_keys)
        result = validate(snapshot)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc),
                          "product_e2e": "HOLD", "store_submission_allowed": False},
                         sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
