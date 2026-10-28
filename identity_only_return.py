"""Return a captured Store Identity through the existing Provisioner CAS writer.

This path intentionally does not select a package version or build an MSIX.
It consumes the GitHub PRE_IDENTITY job and a local authenticated UI receipt,
then delegates the atomic write to GitHubReturnClient.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from package_identity_provisioner import (
    ConflictError,
    GitHubReturnClient,
    HoldError,
    Job,
    OfficialIdentityProvider,
    ProductConfig,
    load_json,
    write_json,
)


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def run_identity_return(*, ledger: dict, operator_job: dict, receipt_path: Path,
                        config: ProductConfig, apply: bool,
                        github: GitHubReturnClient | None = None) -> dict:
    jobs = ledger.get("rotation_cohorts", {}).get("three_d_jobs", [])
    matches = [item for item in jobs if isinstance(item, dict)
               and item.get("slug") == operator_job.get("slug")]
    if len(matches) != 1 or matches[0].get("status") != "PRE_IDENTITY_READY":
        raise HoldError("PRE_IDENTITY GitHub job is not unique and ready")
    queue_job = matches[0]
    if canonical_digest(queue_job) != operator_job.get("queue_job_digest"):
        raise ConflictError("GitHub PRE_IDENTITY queue job digest changed")
    required = {
        "request_id": operator_job.get("request_id"),
        "product_type": "GAME_3D",
        "source_repository": operator_job.get("source_repository"),
        "source_branch": operator_job.get("source_branch"),
        "source_sha": operator_job.get("source_sha"),
        "slug": operator_job.get("slug"),
        "display_name": operator_job.get("display_name"),
        "registration_type": operator_job.get("registration_type"),
        "partner_center_selection": operator_job.get("partner_center_selection"),
    }
    if any(queue_job.get(key) != value for key, value in required.items()):
        raise ConflictError("PRE_IDENTITY job and local operator binding differ")
    if (queue_job.get("artifact_provenance") != "REAL_WINDOWS_EXPORT_VERIFIED"
            or not re.fullmatch(r"[0-9a-f]{64}", str(queue_job.get("expected_exe_sha256", "")))
            or queue_job.get("factory_build_head") != required["source_sha"]):
        raise HoldError("PRE_IDENTITY Factory export evidence is incomplete")
    raw_job = {
        "schema_version": "1.0",
        "request_id": required["request_id"],
        "product_type": "GAME_3D",
        "source_factory": config.source_factory,
        "source_repository": required["source_repository"],
        "source_branch": required["source_branch"],
        "source_sha": required["source_sha"],
        "slug": required["slug"],
        "display_name": required["display_name"],
        "target_owner": config.target_owner,
        "dry_run": False,
        "requested_actions": ["LOOKUP_OFFICIAL_IDENTITY", "PROPOSE_GITHUB_RETURN"],
    }
    job = Job.validate(raw_job, config)
    official = OfficialIdentityProvider(receipt_path).lookup(job)
    if official.get("queue_job_digest") != canonical_digest(queue_job):
        raise ConflictError("Official Identity receipt is not bound to the current queue job")
    package = {
        "kind": "exe",
        "sha256": queue_job["expected_exe_sha256"],
        "signature_status": "PRE_IDENTITY_EXE_NOT_MSIX",
    }
    returned = (github or GitHubReturnClient()).return_identity(
        job, config, official, package, apply=apply,
    )
    return {
        "schema_version": 1,
        "status": returned["status"],
        "request_id": job.request_id,
        "source_sha": job.source_sha,
        "queue_job_digest": canonical_digest(queue_job),
        "identity_return_target": f"products/{job.slug}/store/approved-identity.json",
        "github_return": returned,
        "package_version_gate": "HOLD",
        "store_submission": "NOT_PERFORMED",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--operator-job", type=Path, required=True)
    parser.add_argument("--official-identity", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_identity_return(
            ledger=load_json(args.ledger, 1_000_000),
            operator_job=load_json(args.operator_job, 64_000),
            receipt_path=args.official_identity,
            config=ProductConfig.load(args.config),
            apply=args.apply,
        )
    except (HoldError, ConflictError) as exc:
        result = {"status": exc.status, "errors": [str(exc)], "store_submission": "NOT_PERFORMED"}
    write_json(args.output, result)
    print(json.dumps({"status": result["status"], "output": str(args.output)}, ensure_ascii=False))
    return 0 if result["status"] in {"APPLIED", "EXISTING_VERIFIED", "NOT_APPLIED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
