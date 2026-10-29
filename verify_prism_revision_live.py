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
