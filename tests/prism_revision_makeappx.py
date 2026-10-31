"""Windows SDK MakeAppx and 3D byte QA using the REAL Prism Route Factory export.

Revision-specific unsigned QA only; existing Partner Center product is not re-authenticated; signature, GPU/install/GUI,
Windows-all-auto intake and Store submission are NOT certified.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch
import zipfile

REPO = "shihuiarenjinba-png/3d-game-factory"
SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
RUN = 40901053437
ARTIFACT = 12909162367
QA_SHA = "e84c448e48105d15d2040f87fb279835ddd0119b"

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def api(endpoint):
    return json.loads(subprocess.check_output(
        ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint]))

def main():
    if os.name != "nt":
        raise RuntimeError("Windows SDK MakeAppx required")
    run = api(f"/repos/{REPO}/actions/runs/{RUN}")
    art = api(f"/repos/{REPO}/actions/artifacts/{ARTIFACT}")
    assert run["status"] == "completed" and run["conclusion"] == "success"
    assert run["head_sha"] == SOURCE and run["head_branch"] == "codex/prism-route-trap-tension-20261029"
    assert art["name"] == "godot-3d-factory-export-evidence" and art["expired"] is False
    assert art["workflow_run"]["id"] == RUN and art["digest"].startswith("sha256:")
    out = Path("revision-msix")
    out.mkdir(exist_ok=True)
    archive_path = out / "factory-export.zip"
    with archive_path.open("wb") as stream:
        subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
                        f"/repos/{REPO}/actions/artifacts/{ARTIFACT}/zip"],
                       stdout=stream, check=True)
    assert archive_path.stat().st_size == art["size_in_bytes"]
    assert digest(archive_path) == art["digest"][7:]
    with zipfile.ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == {"candidate.exe", "candidate.pck", "export-evidence.json"}
        evidence = json.loads(archive.read("export-evidence.json"))
        assert evidence["request_id"] == REQUEST and evidence["source_sha"] == SOURCE
        assert evidence["factory_build_head"] == SOURCE and evidence["slug"] == "prism-route-3d"
        for name, field in (("candidate.exe", "exe"), ("candidate.pck", "pck")):
            data = archive.read(name)
            assert hashlib.sha256(data).hexdigest() == evidence[field + "_sha256"]
            assert len(data) == evidence[field + "_size_bytes"]
            (out / name).write_bytes(data)
    assert (out / "candidate.exe").open("rb").read(2) == b"MZ"
    assert (out / "candidate.pck").open("rb").read(4) == b"GDPC"
    qa_root = Path("qa-code")
    qa_head = subprocess.check_output(["git", "-C", str(qa_root), "rev-parse", "HEAD"], text=True).strip()
    assert qa_head == QA_SHA
    sys.path.insert(0, str(qa_root.resolve()))
    sys.path.insert(0, str((qa_root / "tests").resolve()))
    from makeappx_windows_fixture import MANIFEST, PNG
    from msix_artifact_verify import verify_msix
    sdk = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits" / "10" / "bin"
    makeappx = sorted(sdk.glob("*/x64/makeappx.exe"), reverse=True)
    assert makeappx, "Windows SDK MakeAppx unavailable"
    stage = out / "layout"
    (stage / "Game").mkdir(parents=True, exist_ok=True)
    (stage / "Assets").mkdir(parents=True, exist_ok=True)
    (stage / "AppxManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (stage / "Assets" / "Logo.png").write_bytes(PNG)
    shutil.copyfile(out / "candidate.exe", stage / "Game" / "game.exe")
    shutil.copyfile(out / "candidate.pck", stage / "Game" / "game.pck")
    msix = out / "prism-route-3d-sentinel-qa-unsigned.msix"
    subprocess.run([str(makeappx[0]), "pack", "/d", str(stage), "/p", str(msix), "/o"], check=True)
    expected = {"exe_path": "Game/game.exe", "exe_sha256": evidence["exe_sha256"],
                "embed_pck": False, "pck_path": "Game/game.pck",
                "pck_sha256": evidence["pck_sha256"]}
    receipt = {"schema_version": "1.0", "source_factory": "3d-game-factory",
               "request_id": REQUEST, "repository_full_name": REPO,
               "source_sha": SOURCE, "package_sha256": digest(msix),
               "windows_run_id": os.environ["GITHUB_RUN_ID"],
               "runner_evidence_id": "sentinel-revision-unsigned-only", "windows_launch": False,
               "tests": {"executed": 0, "failed": 0, "skipped": 0, "crashes": 0}}
    with patch("msix_artifact_verify.inspect",
               return_value={"status": "EVIDENCE_REVIEW", "errors": []}):
        result = verify_msix(receipt, msix, expected_godot_export=expected)
    checks = ("artifact_bytes_verified", "content_types_verified", "blockmap_verified",
              "payload_executables_verified", "godot_export_bytes_matched")
    assert result["status"] == "HOLD" and all(result[k] is True for k in checks), result
    assert not any(result[k] for k in ("official_identity_verified", "signature_verified",
                                      "windows_launch_verified", "submission_authorized"))
    pck = stage / "Game" / "game.pck"
    with pck.open("r+b") as stream:
        stream.seek(-1, 2)
        old = stream.read(1)
        stream.seek(-1, 2)
        stream.write(bytes([old[0] ^ 1]))
    forged = out / "forged.msix"
    subprocess.run([str(makeappx[0]), "pack", "/d", str(stage), "/p", str(forged), "/o"], check=True)
    with patch("msix_artifact_verify.inspect",
               return_value={"status": "EVIDENCE_REVIEW", "errors": []}):
        bad = verify_msix(dict(receipt, package_sha256=digest(forged)), forged,
                          expected_godot_export=expected)
    assert bad["status"] == "BLOCKED"
    assert any("Godot export payload SHA-256 mismatch" in error for error in bad["errors"]), bad
    forged.unlink()
    report = {"phase": "REAL_SENTINEL_REVISION_MAKEAPPX_BYTE_QA_HOLD_IDENTITY",
              "request_id": REQUEST, "source_sha": SOURCE,
              "factory_run_id": RUN, "factory_artifact_id": ARTIFACT,
              "factory_artifact_sha256": digest(archive_path),
              "exe_sha256": evidence["exe_sha256"], "pck_sha256": evidence["pck_sha256"],
              "msix_sha256": digest(msix), "msix_bytes": msix.stat().st_size,
              "qa_verifier_sha": qa_head, "makeappx_path": str(makeappx[0]),
              "byte_checks": {k: result[k] for k in checks},
              "tampered_pck_repacked_rejected": True, "official_identity": None,
              "signature_verified": False, "windows_install_gpu_gui": "DEFERRED_LOCAL_GATE",
              "store_submission_allowed": False,
              "old_identity_provenance_sha": "15fdcb52e46e35e6de8e87c55af99719c21e09b9",
              "identity_rebinding_status": "HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING",
              "package_version_gate": "HOLD"}
    (out / "makeappx-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
