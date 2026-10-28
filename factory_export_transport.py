"""Authenticated GitHub transport for 3D Factory export provenance.

Never trust run metadata bundled with an artifact or provided by the job.
The exact run and artifact IDs are operator/pipeline-selected references, not
proof; all fields are fetched independently via authenticated GitHub CLI.
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from factory_export_evidence import verify_factory_export_artifact
from package_identity_provisioner import HoldError, inspect_package

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
        if (not isinstance(repo, str) or not REPO.fullmatch(repo)
                or any(part in {".", ".."} for part in repo.split("/"))):
            raise HoldError("Factory export evidence HOLD: invalid Factory repository")
        prefix = f"/repos/{repo}/actions"
        run = self._json(f"{prefix}/runs/{run_id}")
        artifact = self._json(f"{prefix}/artifacts/{artifact_id}")
        size = artifact.get("size_in_bytes")
        if (run.get("id") != run_id or artifact.get("id") != artifact_id
                or type(size) is not int or not 0 < size <= MAX_ARCHIVE_BYTES):
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
                if (result.returncode or archive.stat().st_size != size
                        or not 0 < archive.stat().st_size <= MAX_ARCHIVE_BYTES):
                    raise HoldError("Factory export evidence HOLD: GitHub artifact download failed")
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HoldError("Factory export evidence HOLD: GitHub artifact unavailable") from exc
            # Godot 4.3 can assign different PackedScene UIDs during two fresh
            # imports of the same pinned source. The Factory export is the
            # authoritative payload; local re-export is an independent sanity
            # check, not the package bytes used downstream.
            digest = artifact.get("digest")
            if (not isinstance(digest, str) or not digest.startswith("sha256:")
                    or hashlib.sha256(archive.read_bytes()).hexdigest() != digest[7:]):
                raise HoldError("Factory export evidence HOLD: authenticated ZIP digest mismatch")
            payload_dir = Path(temporary) / "payload"
            payload_dir.mkdir()
            try:
                with zipfile.ZipFile(archive) as zipped:
                    entries = zipped.infolist()
                    names = [entry.filename for entry in entries]
                    if (len(names) != len(set(names))
                            or not {"candidate.exe", "export-evidence.json"}.issubset(names)
                            or set(names) - {"candidate.exe", "candidate.pck", "export-evidence.json"}):
                        raise HoldError("Factory export evidence HOLD: unexpected ZIP members")
                    for entry in entries:
                        if (entry.is_dir() or entry.flag_bits & 1
                                or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                                or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                            raise HoldError("Factory export evidence HOLD: unsafe ZIP member")
                        limit = 16_384 if entry.filename == "export-evidence.json" else 2_000_000_000
                        if entry.file_size > limit:
                            raise HoldError("Factory export evidence HOLD: oversized ZIP member")
                        if entry.filename in {"candidate.exe", "candidate.pck"}:
                            with zipped.open(entry) as source, (payload_dir / entry.filename).open("xb") as output:
                                shutil.copyfileobj(source, output, length=1024 * 1024)
                canonical = inspect_package(payload_dir / "candidate.exe", godot_export=True)
                evidence = verify_factory_export_artifact(job, canonical, archive, run, artifact)
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
                raise HoldError("Factory export evidence HOLD: unsafe/corrupt payload") from exc
            # A local EXE mismatch is not explained by the known Godot PCK UID
            # nondeterminism and remains a hard failure.
            if (local_package.get("kind") != "exe"
                    or local_package.get("godot_export", {}).get("evidence_scope")
                    != "LOCAL_EXPORT_NOT_INDEPENDENT"
                    or local_package.get("sha256") != canonical["sha256"]
                    or local_package.get("size_bytes") != canonical["size_bytes"]):
                raise HoldError("Factory export evidence HOLD: independent EXE differs from Factory")
            local_pck = local_package["godot_export"].get("external_pck_sha256")
            factory_pck = canonical["godot_export"].get("external_pck_sha256")
            if (local_pck is None) != (factory_pck is None):
                raise HoldError("Factory export evidence HOLD: local/Factory PCK presence differs")
            # Never use the nondeterministic local PCK for Store packaging.
            destination = work_root / "authenticated-factory-payload"
            if destination.is_symlink():
                raise HoldError("Factory export evidence HOLD: payload destination is symlinked")
            destination.mkdir(parents=True, exist_ok=True)
            for name in ("candidate.exe", "candidate.pck"):
                source = payload_dir / name
                target = destination / name
                if target.is_symlink() or (target.exists() and not target.is_file()):
                    raise HoldError("Factory export evidence HOLD: unsafe payload destination")
                if source.is_file():
                    os.replace(source, target)
                elif target.is_file():
                    target.unlink()
            evidence["canonical_package_path"] = str((destination / "candidate.exe").resolve())
            evidence["local_reexport_pck_sha256"] = local_pck
            evidence["local_reexport_pck_matches_factory"] = local_pck == factory_pck
            evidence["payload_authority"] = "AUTHENTICATED_FACTORY_ARTIFACT"
            return evidence
