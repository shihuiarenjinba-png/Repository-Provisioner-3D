"""Fail-closed correlation of a *downloaded* Factory Godot export artifact.

This is a pre-Identity byte/provenance contract, not a Store or E2E verdict.
The caller must fetch run and artifact metadata independently from GitHub API,
and must download the artifact ZIP from GitHub. Never accept metadata copied
from inside the ZIP as an authenticated GitHub API response.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import zipfile

from package_identity_provisioner import HoldError

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_NAME = "godot-3d-factory-export-evidence"
REQUIRED = {
    "schema_version", "request_id", "product_type", "source_repository",
    "source_branch", "source_sha", "factory_build_head", "slug",
    "exe_path", "exe_sha256", "exe_size_bytes",
    "pck_path", "pck_sha256", "pck_size_bytes",
}
MAX_EXE_BYTES = 2_000_000_000
MAX_PCK_BYTES = 2_000_000_000


def _reject(reason: str) -> None:
    raise HoldError("Factory export evidence HOLD: " + reason)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_member(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(entry, "r") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_factory_export_artifact(job, local_package: dict, archive_path: Path,
                                   workflow_run: dict, artifact: dict) -> dict:
    """Compare local EXE/PCK with an independently fetched, digest-pinned ZIP.

    GitHub metadata MUST come from authenticated GitHub API reads. The archive
    MUST be downloaded from the corresponding GitHub artifact endpoint.
    A passing result never proves Windows launch, Store Identity, or MSIX QA.
    """
    if not archive_path.is_file() or archive_path.is_symlink():
        _reject("artifact archive is absent or symlinked")
    digest = artifact.get("digest")
    if (artifact.get("name") != ARTIFACT_NAME or artifact.get("expired") is not False
            or not isinstance(digest, str) or not digest.startswith("sha256:")
            or not SHA256.fullmatch(digest[7:])):
        _reject("GitHub artifact metadata is missing, expired, or not a product-export artifact")
    if _sha256(archive_path) != digest[7:]:
        _reject("downloaded ZIP does not match GitHub artifact SHA-256")
    if (workflow_run.get("status") != "completed" or workflow_run.get("conclusion") != "success"
            or workflow_run.get("event") not in {"workflow_dispatch", "push"}
            or type(workflow_run.get("id")) is not int
            or type(artifact.get("id")) is not int
            or not isinstance(artifact.get("workflow_run"), dict)
            or artifact["workflow_run"].get("id") != workflow_run["id"]):
        _reject("artifact is not attached to a successful independent Factory run")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            names = [entry.filename for entry in members]
            if len(names) != len(set(names)):
                _reject("duplicate ZIP members")
            if "export-evidence.json" not in names or "candidate.exe" not in names:
                _reject("required export evidence/EXE missing")
            if set(names) - {"export-evidence.json", "candidate.exe", "candidate.pck"}:
                _reject("unexpected or unsafe ZIP member")
            entries = {entry.filename: entry for entry in members}
            for entry in members:
                if (entry.is_dir() or entry.flag_bits & 1
                        or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                    _reject("ZIP member is a directory, symlink, encrypted, or unsupported")
            if (entries["export-evidence.json"].file_size > 16_384
                    or entries["candidate.exe"].file_size > MAX_EXE_BYTES
                    or ("candidate.pck" in entries and entries["candidate.pck"].file_size > MAX_PCK_BYTES)):
                _reject("artifact member exceeds size limit")
            manifest = json.loads(archive.read("export-evidence.json"))
            if not isinstance(manifest, dict) or set(manifest) != REQUIRED:
                _reject("export receipt schema has missing/unknown fields")
            expected = {
                "schema_version": 1, "request_id": job.request_id,
                "product_type": "GAME_3D", "source_repository": job.source_repository,
                "source_branch": job.source_branch, "source_sha": job.source_sha,
                "slug": job.slug, "exe_path": "candidate.exe",
            }
            if any(manifest.get(k) != v for k, v in expected.items()):
                _reject("request_id/source_sha/slug/source branch correlation mismatch")
            build_head = manifest["factory_build_head"]
            if (not isinstance(build_head, str) or not SHA40.fullmatch(build_head)
                    or set(build_head) == {"0"}
                    or workflow_run.get("head_sha") != build_head
                    or workflow_run.get("head_branch") != job.source_branch
                    or workflow_run.get("head_repository", {}).get("full_name") != job.source_repository):
                _reject("factory_build_head does not match the independent GitHub run")
            if (local_package.get("kind") != "exe"
                    or local_package.get("godot_export", {}).get("evidence_scope")
                    != "LOCAL_EXPORT_NOT_INDEPENDENT"):
                _reject("local Godot EXE inspection evidence is missing")
            exe_sha = manifest["exe_sha256"]
            exe_size = manifest["exe_size_bytes"]
            if (not isinstance(exe_sha, str) or not SHA256.fullmatch(exe_sha)
                    or type(exe_size) is not int or exe_size <= 0
                    or exe_size != entries["candidate.exe"].file_size
                    or exe_sha != _hash_member(archive, entries["candidate.exe"])
                    or exe_sha != local_package.get("sha256")
                    or exe_size != local_package.get("size_bytes")
                    or exe_sha != local_package["godot_export"].get("exe_sha256")):
                _reject("Factory EXE and local inspected EXE bytes differ")
            has_pck = "candidate.pck" in entries
            if has_pck != (manifest["pck_path"] == "candidate.pck"):
                _reject("PCK presence/path mismatch")
            pck_sha, pck_size = manifest["pck_sha256"], manifest["pck_size_bytes"]
            if has_pck:
                if (not isinstance(pck_sha, str) or not SHA256.fullmatch(pck_sha)
                        or type(pck_size) is not int or pck_size < 4
                        or pck_size != entries["candidate.pck"].file_size
                        or pck_sha != _hash_member(archive, entries["candidate.pck"])
                        or pck_sha != local_package["godot_export"].get("external_pck_sha256")
                        or pck_size != local_package["godot_export"].get("external_pck_size_bytes")):
                    _reject("Factory PCK and local inspected PCK bytes differ")
            elif (manifest["pck_path"] is not None or pck_sha is not None
                  or pck_size is not None
                  or local_package["godot_export"].get("external_pck_sha256") is not None
                  or local_package["godot_export"].get("external_pck_size_bytes") is not None):
                _reject("embedded-PCK contract disagrees with local inspection")
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, HoldError):
            raise
        _reject("invalid or corrupt export artifact ZIP")
    return {
        "status": "PRE_IDENTITY_BYTES_CORRELATED",
        "evidence_scope": "FACTORY_ARTIFACT_BYTES_NOT_STORE_E2E",
        "request_id": job.request_id,
        "source_sha": job.source_sha,
        "factory_build_head": build_head,
        "slug": job.slug,
        "workflow_run_id": workflow_run["id"],
        "artifact_id": artifact["id"],
        "artifact_sha256": digest[7:],
        "exe_sha256": exe_sha,
        "external_pck_sha256": pck_sha,
        "post_identity_ready": False,
        "windows_install_gpu_gui_verified": False,
    }
