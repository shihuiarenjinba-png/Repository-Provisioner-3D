"""Authenticated GitHub transport for 3D Factory export provenance.

Never trust run metadata bundled with an artifact or provided by the job.
The exact run and artifact IDs are operator/pipeline-selected references, not
proof; all fields are fetched independently via authenticated GitHub CLI.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from factory_export_evidence import verify_factory_export_artifact
from package_identity_provisioner import HoldError

REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_ARCHIVE_BYTES = 2_200_000_000


class FactoryExportTransport:
    def __init__(self, gh: str | None = None):
        self.gh = gh

    def _gh(self) -> str:
        executable = self.gh or shutil.which("gh")
        if not executable:
            raise HoldError("Factory export evidence HOLD: authenticated gh CLI unavailable")
        return executable

    def _json(self, endpoint: str) -> dict:
        try:
            result = subprocess.run(
                [self._gh(), "api", "--hostname", "github.com", "--method", "GET", endpoint],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90, check=False,
            )
            if result.returncode or len(result.stdout) > 1_000_000:
                raise HoldError("Factory export evidence HOLD: GitHub metadata API read failed")
            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            return data
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            raise HoldError("Factory export evidence HOLD: authenticated GitHub metadata unavailable") from exc

    def verify(self, job, local_package: dict, *, run_id: int | None,
               artifact_id: int | None, work_root: Path) -> dict:
        if (type(run_id) is not int or run_id <= 0
                or type(artifact_id) is not int or artifact_id <= 0):
            raise HoldError("Factory export evidence HOLD: --factory-run-id and --factory-artifact-id required")
        repo = job.source_repository
        if not isinstance(repo, str) or not REPO.fullmatch(repo):
            raise HoldError("Factory export evidence HOLD: invalid Factory repository")
        prefix = f"/repos/{repo}/actions"
        run = self._json(f"{prefix}/runs/{run_id}")
        artifact = self._json(f"{prefix}/artifacts/{artifact_id}")
        if (run.get("id") != run_id or artifact.get("id") != artifact_id
                or artifact.get("size_in_bytes", 0) > MAX_ARCHIVE_BYTES
                or artifact.get("size_in_bytes", 0) <= 0
                or type(artifact.get("size_in_bytes")) is not int):
            raise HoldError("Factory export evidence HOLD: GitHub run/artifact metadata mismatch")
        work_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="factory-export-", dir=work_root) as temporary:
            archive = Path(temporary) / "downloaded-factory-artifact.zip"
            try:
                with archive.open("wb") as stream:
                    result = subprocess.run(
                        [self._gh(), "api", "--hostname", "github.com", "--method", "GET",
                         f"{prefix}/artifacts/{artifact_id}/zip"],
                        stdout=stream, stderr=subprocess.DEVNULL, timeout=300, check=False,
                    )
                if result.returncode or not 0 < archive.stat().st_size <= MAX_ARCHIVE_BYTES:
                    raise HoldError("Factory export evidence HOLD: GitHub artifact download failed")
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HoldError("Factory export evidence HOLD: GitHub artifact unavailable") from exc
            return verify_factory_export_artifact(job, local_package, archive, run, artifact)
