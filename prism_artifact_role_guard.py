"""Fail-closed source-role selection for independently audited Prism 3D artifacts.

This prevents recency-based ORIGINAL/SENTINEL artifact substitution. The
checked-in receipt is a historical audit, not authenticated live GitHub data,
an approved Store Identity, or a permission to build/submit a Store package.
"""
import argparse
import json
from pathlib import Path
import re

RECEIPT = Path(__file__).resolve().parent / "handoffs/prism-route-3d-artifact-source-role-receipt-20261031.json"
ORIGINAL = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
SENTINEL = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
ROLE_SOURCE = {
    "original_factory": ORIGINAL,
    "latest_original_pre": ORIGINAL,
    "latest_original_unsigned_msix": ORIGINAL,
    "sentinel_factory": SENTINEL,
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ArtifactRoleError(ValueError):
    """Artifact is not safely attributable to the requested source revision."""


def select_audited_artifact(receipt, *, role, artifact_id, expected_source_sha):
    """Return a HOLD-only historical role receipt, never a live authentication."""
    if not isinstance(receipt, dict):
        raise ArtifactRoleError("missing audit receipt")
    if (receipt.get("schema_version") != 1
            or receipt.get("verification_kind") != "INDEPENDENT_DOWNLOADED_BYTES_SOURCE_ROLE_CLASSIFICATION"
            or receipt.get("product") != "Prism Route 3D"
            or receipt.get("slug") != "prism-route-3d"):
        raise ArtifactRoleError("wrong audit receipt")
    for key, sha, request in (
        ("original_revision", ORIGINAL, "3d-prism-route-3d-" + ORIGINAL[:12]),
        ("sentinel_revision", SENTINEL, "3d-prism-route-3d-" + SENTINEL[:12]),
    ):
        revision = receipt.get(key)
        if not isinstance(revision, dict) or revision.get("source_sha") != sha or revision.get("request_id") != request:
            raise ArtifactRoleError("revision provenance mismatch")
    payloads = receipt.get("source_payloads")
    if not isinstance(payloads, dict):
        raise ArtifactRoleError("missing payload hashes")
    old_pck = payloads.get("original_pck_sha256")
    new_pck = payloads.get("sentinel_pck_sha256")
    if (not isinstance(old_pck, str) or not HEX64.fullmatch(old_pck)
            or not isinstance(new_pck, str) or not HEX64.fullmatch(new_pck)
            or old_pck == new_pck):
        raise ArtifactRoleError("unproven distinct PCK payloads")
    comparisons = receipt.get("comparisons")
    required = {
        "latest_pre_source_is_original_not_sentinel": True,
        "latest_unsigned_msix_source_is_original_not_sentinel": True,
        "latest_unsigned_msix_embedded_exe_matches_original_factory": True,
        "latest_unsigned_msix_embedded_pck_matches_original_factory": True,
        "latest_unsigned_msix_embedded_pck_matches_sentinel_factory": False,
        "original_and_sentinel_exe_sha256_equal": True,
        "original_and_sentinel_pck_sha256_equal": False,
        "latest_unsigned_msix_signature_present": False,
        "latest_unsigned_msix_fixture_identity": "Example.ThreeD.Fixture",
        "cross_revision_artifact_promotion_allowed": False,
    }
    if not isinstance(comparisons, dict) or any(
            type(comparisons.get(k)) is not type(v) or comparisons[k] != v
            for k, v in required.items()):
        raise ArtifactRoleError("source-role byte comparison not proven")
    if role not in ROLE_SOURCE:
        raise ArtifactRoleError("artifact role not independently audited")
    if (not isinstance(expected_source_sha, str)
            or expected_source_sha != ROLE_SOURCE[role]):
        raise ArtifactRoleError("requested source does not own artifact role")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ROLE_SOURCE):
        raise ArtifactRoleError("incomplete audited artifact set")
    ids = []
    for name, item in artifacts.items():
        if (not isinstance(item, dict)
                or type(item.get("artifact_id")) is not int or item["artifact_id"] <= 0
                or type(item.get("run_id")) is not int or item["run_id"] <= 0
                or type(item.get("downloaded_zip_size_bytes")) is not int
                or item["downloaded_zip_size_bytes"] <= 0
                or not isinstance(item.get("downloaded_zip_sha256"), str)
                or not HEX64.fullmatch(item["downloaded_zip_sha256"])
                or item.get("digest_verified_against_github_metadata") is not True):
            raise ArtifactRoleError("incomplete downloaded-byte audit")
        expected_repo = ("shihuiarenjinba-png/3d-game-factory" if name.endswith("factory")
                         else "shihuiarenjinba-png/Repository-Provisioner-3D")
        if item.get("repo") != expected_repo:
            raise ArtifactRoleError("artifact repository mismatch")
        ids.append(item["artifact_id"])
    if len(set(ids)) != len(ids):
        raise ArtifactRoleError("duplicate artifact ID")
    item = artifacts[role]
    if type(artifact_id) is not int or artifact_id != item["artifact_id"]:
        raise ArtifactRoleError("artifact ID is not pinned to requested role")
    decision = receipt.get("decision")
    if (not isinstance(decision, dict) or decision.get("product_e2e") != "HOLD"
            or decision.get("official_identity_cas") != "HOLD"
            or decision.get("signed_msix") != "HOLD"
            or decision.get("windows_all_auto_intake") != "HOLD"
            or decision.get("second_3d_product_allowed") is not False):
        raise ArtifactRoleError("unsafe downstream authorization")
    return {
        "status": "HOLD_HISTORICAL_SOURCE_ROLE_DOCUMENTED",
        "role": role, "artifact_id": artifact_id,
        "source_sha": expected_source_sha,
        "request_id": "3d-prism-route-3d-" + expected_source_sha[:12],
        "zip_sha256": item["downloaded_zip_sha256"],
        "zip_bytes": item["downloaded_zip_size_bytes"],
        "pck_sha256": new_pck if expected_source_sha == SENTINEL else old_pck,
        "live_github_artifact_authentication": False,
        "package_version_approved": False,
        "store_submission_allowed": False,
        "product_e2e": "HOLD",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, default=RECEIPT)
    parser.add_argument("--role", required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.receipt.read_text(encoding="utf-8"))
        result = select_audited_artifact(data, role=args.role,
                                         artifact_id=args.artifact_id,
                                         expected_source_sha=args.source_sha)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc),
                          "store_submission_allowed": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
