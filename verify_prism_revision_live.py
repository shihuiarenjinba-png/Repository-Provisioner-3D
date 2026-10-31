"""Read-only live GitHub metadata check for the pinned Prism Route 3D revision.

This is a HOLD-only consumer tool, not a Store package/Identity authorization.
Requires an authenticated GitHub CLI (GH_TOKEN or gh auth login).
Usage: python verify_prism_revision_live.py [--handoff PATH]
"""
import argparse
import json
from pathlib import Path
import subprocess

from prism_revision_handoff_contract import RevisionHandoffError, verify_github_metadata

DEFAULT_HANDOFF = Path(__file__).resolve().parent / "handoffs/prism-route-3d-sentinel-revision-20261029.json"


def _github_json(endpoint):
    """Use GitHub CLI's authenticated, read-only GET API; fail closed on errors."""
    result = subprocess.run(
        ["gh", "api", "--method", "GET", endpoint],
        capture_output=True, text=True, check=True, timeout=30,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("GitHub API response is not an object")
    return value


def _github_run(repo, run_id):
    return _github_json(f"/repos/{repo}/actions/runs/{run_id}")


def _github_artifacts(repo, run_id):
    response = _github_json(
        f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    )
    artifacts, total = response.get("artifacts"), response.get("total_count")
    if not isinstance(artifacts, list) or type(total) is not int or total != len(artifacts):
        # Do not silently trust a truncated first page or a malformed response.
        raise ValueError("incomplete GitHub artifact listing")
    return artifacts


def _authenticate_pinned_verifier(handoff):
    """Independently authenticate the pinned successful byte-verifier job.

    A self-consistent JSON receipt is not proof of a GitHub run. This check
    fetches the exact run and job/step via read-only authenticated GitHub API.
    It does not re-download ZIP bytes or authorize Store submission.
    """
    claim = handoff["pinned_snapshot_verification"]
    repo = "shihuiarenjinba-png/Repository-Provisioner-3D"
    run_id = claim["verified_workflow_run_id"]
    job_id = claim["verified_job_id"]
    run = _github_run(repo, run_id)
    job = _github_json(f"/repos/{repo}/actions/jobs/{job_id}")
    if (type(run.get("id")) is not int or run["id"] != run_id
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("head_sha") != claim["verified_workflow_head_sha"]
            or run.get("head_branch") != "codex/e2e-belt-connection-20261027"
            or run.get("event") != "push"
            or run.get("path") != ".github/workflows/prism-revision-provisioner.yml"
            or type(run.get("workflow_id")) is not int
            or run["workflow_id"] != 400477810
            or not isinstance(run.get("repository"), dict)
            or type(run["repository"].get("id")) is not int
            or run["repository"]["id"] != 1434261585
            or not isinstance(run.get("head_repository"), dict)
            or type(run["head_repository"].get("id")) is not int
            or run["head_repository"]["id"] != 1434261585):
        raise RevisionHandoffError("pinned verifier GitHub run mismatch")
    if (type(job.get("id")) is not int or job["id"] != job_id
            or type(job.get("run_id")) is not int or job["run_id"] != run_id
            or job.get("name") != "prism-revision-pre"
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"):
        raise RevisionHandoffError("pinned verifier GitHub job mismatch")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise RevisionHandoffError("pinned verifier job steps missing")
    matches = [step for step in steps if isinstance(step, dict)
               and step.get("name") == claim["verified_step"]]
    if (len(matches) != 1 or matches[0].get("status") != "completed"
            or matches[0].get("conclusion") != claim["verified_step_conclusion"]
            or matches[0].get("conclusion") != "success"):
        raise RevisionHandoffError("pinned verifier GitHub step mismatch")
    return {"pinned_verifier_job_authenticated": True,
            "pinned_verifier_job_id": job_id,
            "pinned_verifier_step_authenticated": True,
            "new_output_artifact_bytes_reverified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, default=DEFAULT_HANDOFF)
    args = parser.parse_args(argv)
    try:
        handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
        receipt = verify_github_metadata(
            handoff, fetch_run=_github_run, fetch_artifacts=_github_artifacts
        )
        if (receipt.get("status") != "GITHUB_METADATA_MATCH_HOLD_PAYLOAD_NOT_VERIFIED"
                or receipt.get("product_e2e") != "HOLD"
                or receipt.get("store_submission_allowed") is not False):
            raise RevisionHandoffError("unexpected authorization in HOLD-only receipt")
        receipt.update(_authenticate_pinned_verifier(handoff))
    except (OSError, ValueError, subprocess.SubprocessError, TimeoutError) as exc:
        # Avoid leaking tokens, HTTP response bodies or sensitive subprocess output.
        print(json.dumps({"status": "HOLD", "reason": type(exc).__name__,
                          "github_metadata_verified": False,
                          "store_submission_allowed": False}, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
