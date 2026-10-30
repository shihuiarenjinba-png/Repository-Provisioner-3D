"""Fail-closed byte-level verification of the pinned Prism Sentinel Factory and unsigned QA artifacts.

A successful result proves historical ZIP and inner EXE/PCK/MSIX byte
correlation only. It never approves Identity, signing, Windows intake or Store.
"""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile
from xml.etree import ElementTree

from prism_revision_handoff_contract import (
    PINNED_SENTINEL_SOURCE_SHA, RevisionHandoffError,
    validate_revision_handoff, verify_github_metadata,
)
from verify_prism_revision_live import DEFAULT_HANDOFF, _github_run, _github_artifacts

FACTORY_REPO = "shihuiarenjinba-png/3d-game-factory"
PROVISIONER_REPO = "shihuiarenjinba-png/Repository-Provisioner-3D"
MAX_ARCHIVE_BYTES = 150 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
MAX_ENTRIES = 30


def _safe_zip(raw):
    archive = zipfile.ZipFile(BytesIO(raw))
    files = archive.infolist()
    if not files or len(files) > MAX_ENTRIES:
        archive.close()
        raise RevisionHandoffError("unsafe ZIP entry count")
    names, total = set(), 0
    for info in files:
        name = info.filename
        parts = name.replace("\\", "/").split("/")
        if (not name or name.startswith("/") or "\\" in name
                or any(p in ("", ".", "..") for p in parts)
                or ":" in name or name in names or info.is_dir()
                or info.flag_bits & 1
                or ((info.external_attr >> 16) & 0o170000) == 0o120000):
            archive.close()
            raise RevisionHandoffError("unsafe ZIP entry")
        names.add(name)
        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            archive.close()
            raise RevisionHandoffError("ZIP uncompressed size limit")
    return archive


def _verify_archive(raw, item):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise RevisionHandoffError("missing or oversized artifact ZIP")
    if (len(raw) != item["archive_bytes"]
            or hashlib.sha256(raw).hexdigest() != item["archive_digest"][7:]):
        raise RevisionHandoffError("GitHub artifact ZIP byte mismatch")
    return _safe_zip(raw)


def _json_entry(archive, name):
    if name not in archive.namelist():
        raise RevisionHandoffError("missing evidence JSON")
    with archive.open(name) as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise RevisionHandoffError("oversized evidence JSON")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise RevisionHandoffError("evidence JSON must be an object")
    return result


def _check_member(archive, name, expected_sha, expected_bytes, magic):
    if (name not in archive.namelist() or type(expected_bytes) is not int
            or expected_bytes <= 0 or archive.getinfo(name).file_size != expected_bytes):
        raise RevisionHandoffError("missing payload or length mismatch")
    with archive.open(name) as stream:
        header = stream.read(len(magic))
        digest = hashlib.sha256(header)
        size = len(header)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    if header != magic or size != expected_bytes or digest.hexdigest() != expected_sha:
        raise RevisionHandoffError("payload magic/SHA mismatch")



def _verify_unsigned_qa_fixture_manifest(archive):
    """Confirm the unsigned MSIX is a QA fixture, never the Prism Store identity."""
    # MakeAppx QA is deliberately unsigned. A recomputed report/ZIP digest
    # must never let a signed (or signature-bearing) package pose as this fixture.
    if "AppxSignature.p7x" in archive.namelist():
        raise RevisionHandoffError("signed package cannot pass unsigned QA")
    name = "AppxManifest.xml"
    if name not in archive.namelist() or archive.getinfo(name).file_size > 65536:
        raise RevisionHandoffError("missing or oversized unsigned QA manifest")
    try:
        root = ElementTree.fromstring(archive.read(name))
    except ElementTree.ParseError as exc:
        raise RevisionHandoffError("malformed unsigned QA manifest") from exc
    ns = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    rescap = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
    if root.tag != f"{{{ns}}}Package":
        raise RevisionHandoffError("wrong unsigned QA manifest namespace")
    identity = root.find(f"{{{ns}}}Identity")
    application = root.find(f"{{{ns}}}Applications/{{{ns}}}Application")
    capability = root.find(f"{{{ns}}}Capabilities/{{{rescap}}}Capability")
    if (identity is None or identity.get("Name") != "Example.ThreeD.Fixture"
            or identity.get("Publisher") != "CN=Offline QA Fixture"
            or identity.get("Version") != "1.0.0.0"
            or identity.get("ProcessorArchitecture") != "x64"
            or application is None
            or application.get("Executable") != r"Game\game.exe"
            or application.get("EntryPoint") != "Windows.FullTrustApplication"
            or capability is None or capability.get("Name") != "runFullTrust"):
        raise RevisionHandoffError("unsigned QA fixture manifest mismatch")
    return True


def verify_payload_bytes(handoff, fetch_zip, *, now=None):
    """Verify real ZIP bytes and inner payload, without granting authorization."""
    validate_revision_handoff(handoff, now=now)
    evidence = handoff["evidence"]
    factory_item, qa_item = evidence["factory"], evidence["unsigned_makeappx"]
    factory_raw = fetch_zip(FACTORY_REPO, factory_item["artifact_id"])
    with _verify_archive(factory_raw, factory_item) as factory:
        if set(factory.namelist()) != {"candidate.exe", "candidate.pck", "export-evidence.json"}:
            raise RevisionHandoffError("unexpected Factory ZIP layout")
        record = _json_entry(factory, "export-evidence.json")
        source = PINNED_SENTINEL_SOURCE_SHA
        expected = {
            "source_sha": source,
            "factory_build_head": source,
            "source_branch": handoff["source_branch"],
            "source_repository": FACTORY_REPO,
            "request_id": handoff["request_id"],
            "slug": handoff["slug"],
            "exe_path": "candidate.exe",
            "pck_path": "candidate.pck",
        }
        if any(record.get(k) != v for k, v in expected.items()):
            raise RevisionHandoffError("Factory provenance mismatch")
        for kind, magic in (("exe", b"MZ"), ("pck", b"GDPC")):
            _check_member(factory, f"candidate.{kind}",
                          record.get(f"{kind}_sha256"),
                          record.get(f"{kind}_size_bytes"), magic)

    qa_raw = fetch_zip(PROVISIONER_REPO, qa_item["artifact_id"])
    with _verify_archive(qa_raw, qa_item) as qa:
        names = set(qa.namelist())
        msix_names = [n for n in names if n.endswith("prism-route-3d-sentinel-qa-unsigned.msix")]
        report_names = [n for n in names if n.endswith("makeappx-evidence.json")]
        if len(msix_names) != 1 or len(report_names) != 1 or len(names) != 2:
            raise RevisionHandoffError("unexpected unsigned QA ZIP layout")
        report = _json_entry(qa, report_names[0])
        expected_report = {
            "source_sha": source,
            "request_id": handoff["request_id"],
            "factory_run_id": factory_item["run_id"],
            "factory_artifact_id": factory_item["artifact_id"],
            "factory_artifact_sha256": factory_item["archive_digest"][7:],
            "exe_sha256": record["exe_sha256"],
            "pck_sha256": record["pck_sha256"],
            "signature_verified": False,
            "store_submission_allowed": False,
            "package_version_gate": "HOLD",
            "identity_rebinding_status": "HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING",
        }
        if any(report.get(k) != v for k, v in expected_report.items()):
            raise RevisionHandoffError("unsigned QA evidence mismatch")
        with qa.open(msix_names[0]) as stream:
            msix_raw = stream.read(MAX_ARCHIVE_BYTES + 1)
        if (len(msix_raw) > MAX_ARCHIVE_BYTES
                or type(report.get("msix_bytes")) is not int
                or len(msix_raw) != report["msix_bytes"]
                or hashlib.sha256(msix_raw).hexdigest() != report.get("msix_sha256")):
            raise RevisionHandoffError("unsigned MSIX byte mismatch")
        with _safe_zip(msix_raw) as msix:
            for kind, magic in (("exe", b"MZ"), ("pck", b"GDPC")):
                _check_member(msix, f"Game/game.{kind}",
                              record[f"{kind}_sha256"],
                              record[f"{kind}_size_bytes"], magic)
            _verify_unsigned_qa_fixture_manifest(msix)
    return {
        "status": "FACTORY_AND_UNSIGNED_MSIX_BYTES_CORRELATED_HOLD_IDENTITY",
        "source_sha": source,
        "request_id": handoff["request_id"],
        "artifact_zip_bytes_verified": True,
        "inner_exe_pck_msix_verified": True,
        "unsigned_qa_fixture_identity_detected": True,
        "product_identity_verified": False,
        "official_identity_cas_verified": False,
        "signature_verified": False,
        "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD",
        "store_submission_allowed": False,
    }


def _download_zip(repo, artifact_id):
    with tempfile.TemporaryFile() as output:
        subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET",
             f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"],
            stdout=output, stderr=subprocess.PIPE, check=True, timeout=180,
        )
        if output.tell() > MAX_ARCHIVE_BYTES:
            raise RevisionHandoffError("download exceeds archive limit")
        output.seek(0)
        return output.read()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, default=DEFAULT_HANDOFF)
    args = parser.parse_args(argv)
    try:
        handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
        metadata = verify_github_metadata(
            handoff, fetch_run=_github_run, fetch_artifacts=_github_artifacts)
        if metadata.get("store_submission_allowed") is not False:
            raise RevisionHandoffError("unsafe metadata authorization")
        receipt = verify_payload_bytes(handoff, _download_zip)
    except (OSError, ValueError, subprocess.SubprocessError, TimeoutError,
            zipfile.BadZipFile, EOFError) as exc:
        print(json.dumps({"status": "HOLD", "reason": type(exc).__name__,
                          "artifact_zip_bytes_verified": False,
                          "store_submission_allowed": False}, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
