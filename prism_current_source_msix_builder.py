"""Fail-closed current-source Prism Route 3D unsigned MSIX builder.

This module never performs Identity CAS, Store submission, signing, or publish.
A product MSIX can be created only after a current-source official Identity
return, its authoritative four-part Version, and user-approved Store PNGs have
all been independently supplied and matched to the pinned Factory bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from prism_current_source_package_readiness import (
    SOURCE_SHA,
    REQUEST_ID,
    FACTORY_ARTIFACT_ID,
    FACTORY_ZIP_SHA256,
    EXE_SHA256,
    PCK_SHA256,
    QA_CUSTODY_ARTIFACT_ID,
    QA_CUSTODY_ARTIFACT_SHA256,
    validate as validate_current_handoff,
)

PRODUCT_NAME = "Prism Route 3D"
REGISTRATION_TYPE = "MSIX_OR_PWA_GAME"
EXPECTED_EXE_SIZE = 84214784
EXPECTED_PCK_SIZE = 6987584
EXPECTED_CUSTODY_SIZE = 167283608
MAKEAPPX_PATH = (
    r"C:\Program Files (x86)\Windows Kits\10\bin"
    r"\10.0.26100.0\x64\MakeAppx.exe"
)
MAKEAPPX_SHA256 = "58d5e69fd0322f960afbe34afed0eda66a5d001811ee838d1c7165130c3d55e5"
MAKEAPPX_FILE_VERSION = "10.0.26100.9457 (WinBuild.160101.0800)"
APPX_NS = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
UAP_NS = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
RESCAP_NS = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CRC32_RE = re.compile(r"[0-9a-f]{8}\Z")
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
STORE_ID_RE = re.compile(r"[A-Z0-9]{12}\Z")
PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9.]+\Z")
PACKAGE_SID_RE = re.compile(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+\Z")

EXPECTED_ASSETS = {
    "Assets/StoreLogo.png": (50, 50),
    "Assets/Square150x150Logo.png": (150, 150),
    "Assets/Square44x44Logo.png": (44, 44),
}
IDENTITY_FIELDS = (
    "store_id",
    "reserved_display_name",
    "package_identity_name",
    "publisher",
    "publisher_display_name",
    "pfn",
    "package_sid",
)


class BuildGateError(ValueError):
    """A prerequisite is absent, stale, inconsistent, or unsafe."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildGateError(message)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildGateError("duplicate JSON key: " + str(key))
        result[key] = value
    return result


def load_json(path: str | Path) -> tuple[dict, bytes]:
    raw = Path(path).read_bytes()
    _require(bool(raw), "empty JSON input: " + str(path))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildGateError("invalid UTF-8 JSON input: " + str(path)) from exc
    _require(type(value) is dict, "JSON root must be an object: " + str(path))
    return value, raw


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc_timestamp(value, field: str) -> None:
    _require(type(value) is str and value.endswith("Z"), field + " must be UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BuildGateError(field + " is invalid") from exc
    _require(parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0,
             field + " must be UTC")


def _safe_file(path: str | Path, label: str) -> Path:
    value = Path(path)
    _require(not value.is_symlink(), label + " must not be a symlink")
    _require(value.is_file(), label + " is missing")
    return value.resolve(strict=True)


def _safe_child(root: str | Path, relative: str, label: str) -> Path:
    base = Path(root).resolve(strict=True)
    candidate = base / relative
    _require(not candidate.is_symlink(), label + " must not be a symlink")
    resolved = candidate.resolve(strict=True)
    _require(resolved == base or base in resolved.parents, label + " escapes its approved root")
    _require(resolved.is_file(), label + " is missing")
    return resolved


def _validate_version(value: str) -> str:
    _require(type(value) is str and VERSION_RE.fullmatch(value) is not None,
             "authoritative Package Version must contain exactly four numeric parts")
    parts = [int(part) for part in value.split(".")]
    _require(all(0 <= part <= 65535 for part in parts),
             "Package Version part exceeds the MSIX 16-bit range")
    _require(parts != [0, 0, 0, 0], "zero Package Version is not accepted")
    return value


def _validate_identity(identity_return: dict) -> dict:
    _require(type(identity_return) is dict, "official Identity return is missing")
    _require(identity_return.get("schema_version") == 1, "Identity return schema mismatch")
    _require(identity_return.get("authority") == "MICROSOFT_PARTNER_CENTER_OFFICIAL_UI",
             "Identity authority is not the official Partner Center UI")
    _require(identity_return.get("approval_status") == "APPROVED",
             "current-source Identity is not officially approved")
    _require(identity_return.get("official_ui_capture_verified") is True,
             "official Identity UI capture is not verified")
    _require(identity_return.get("identity_rebind_status") == "VERIFIED_CURRENT_SOURCE_CAS",
             "current-source Identity rebind/CAS is not verified")
    _require(identity_return.get("source_sha") == SOURCE_SHA,
             "Identity source SHA is stale or mismatched")
    _require(identity_return.get("request_id") == REQUEST_ID,
             "Identity request ID is stale or mismatched")
    _require(identity_return.get("factory_artifact_id") == FACTORY_ARTIFACT_ID,
             "Identity return is not bound to the current Factory artifact")
    _require(identity_return.get("exe_sha256") == EXE_SHA256,
             "Identity return EXE SHA does not match current Factory bytes")
    _require(identity_return.get("pck_sha256") == PCK_SHA256,
             "Identity return PCK SHA does not match current Factory bytes")
    _require(SHA256_RE.fullmatch(str(identity_return.get("capture_receipt_sha256", ""))) is not None,
             "official Identity capture receipt SHA is missing")
    _require(identity_return.get("operator_attested") is True,
             "operator attestation for official Identity is missing")
    _require(type(identity_return.get("operator")) is str and len(identity_return["operator"].strip()) >= 3,
             "official Identity operator is missing")
    _utc_timestamp(identity_return.get("retrieved_at_utc"), "Identity retrieved_at_utc")

    identity = identity_return.get("identity")
    _require(type(identity) is dict and set(identity) == set(IDENTITY_FIELDS),
             "official Identity fields are missing or unexpected")
    _require(STORE_ID_RE.fullmatch(str(identity.get("store_id", ""))) is not None,
             "Store ID is malformed")
    _require(identity.get("reserved_display_name") == PRODUCT_NAME,
             "reserved display name does not match Prism Route 3D")
    name = identity.get("package_identity_name")
    _require(type(name) is str and PACKAGE_NAME_RE.fullmatch(name) is not None,
             "Package Identity Name is malformed")
    publisher = identity.get("publisher")
    _require(type(publisher) is str and publisher.startswith("CN=") and len(publisher) > 3,
             "Publisher is missing or malformed")
    _require(type(identity.get("publisher_display_name")) is str
             and identity["publisher_display_name"].strip(),
             "PublisherDisplayName is missing")
    pfn = identity.get("pfn")
    _require(type(pfn) is str and pfn.startswith(name + "_")
             and re.fullmatch(re.escape(name) + r"_[A-Za-z0-9]+", pfn) is not None,
             "Package Family Name is malformed or inconsistent with Identity Name")
    _require(PACKAGE_SID_RE.fullmatch(str(identity.get("package_sid", ""))) is not None,
             "Package SID is malformed")
    _validate_version(identity_return.get("package_version"))
    return identity


def _validate_version_return(version_return: dict, identity_return: dict,
                             identity_raw: bytes, identity: dict) -> str:
    _require(type(version_return) is dict, "authoritative Package Version return is missing")
    _require(version_return.get("schema_version") == 1, "Version return schema mismatch")
    _require(version_return.get("authority") == "PARTNER_CENTER_APPROVED_IDENTITY_RETURN",
             "Version is not sourced from the approved Partner Center Identity return")
    _require(version_return.get("approval_status") == "APPROVED",
             "Package Version is not approved")
    _require(version_return.get("source_sha") == SOURCE_SHA
             and version_return.get("request_id") == REQUEST_ID,
             "Version source/request binding mismatch")
    _require(version_return.get("identity_return_sha256") == sha256_bytes(identity_raw),
             "Version return does not reference the exact official Identity return bytes")
    _utc_timestamp(version_return.get("retrieved_at_utc"), "Version retrieved_at_utc")
    version = _validate_version(version_return.get("package_version"))
    _require(version == identity_return.get("package_version"),
             "Version differs from the official Identity return")
    for field in IDENTITY_FIELDS:
        _require(version_return.get(field) == identity.get(field),
                 "Version return Identity mismatch: " + field)
    return version


def _validate_binding(binding: dict, identity: dict, version: str) -> None:
    _require(type(binding) is dict, "current-source package binding is missing")
    _require(binding.get("schema_version") == 1, "package binding schema mismatch")
    _require(binding.get("source_sha") == SOURCE_SHA and binding.get("request_id") == REQUEST_ID,
             "package binding source/request mismatch")
    _require(binding.get("registration_type") == REGISTRATION_TYPE,
             "package binding registration route mismatch")
    _require(binding.get("identity") == identity,
             "package binding Publisher/PFN/SID or Identity fields mismatch")
    _require(binding.get("package_version") == version,
             "package binding Version mismatch")


def _png_details(data: bytes) -> tuple[int, int, str]:
    _require(data.startswith(PNG_SIGNATURE), "Store asset is not a PNG")
    offset = len(PNG_SIGNATURE)
    width = height = None
    saw_iend = False
    while offset < len(data):
        _require(offset + 12 <= len(data), "PNG chunk header is truncated")
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        start = offset + 8
        end = start + length
        _require(end + 4 <= len(data), "PNG chunk payload is truncated")
        chunk_data = data[start:end]
        stored_crc = struct.unpack(">I", data[end:end + 4])[0]
        actual_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        _require(stored_crc == actual_crc, "PNG internal chunk CRC mismatch")
        if chunk_type == b"IHDR":
            _require(width is None and length == 13, "PNG IHDR is invalid")
            width, height = struct.unpack(">II", chunk_data[:8])
        if chunk_type == b"IEND":
            _require(length == 0 and end + 4 == len(data), "PNG IEND is invalid or not final")
            saw_iend = True
            offset = end + 4
            break
        offset = end + 4
    _require(width is not None and height is not None and saw_iend, "PNG structure is incomplete")
    return width, height, f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


def _validate_assets(asset_approval: dict, asset_root: str | Path) -> dict[str, Path]:
    _require(type(asset_approval) is dict, "user-approved Store asset receipt is missing")
    _require(asset_approval.get("schema_version") == 1, "Store asset receipt schema mismatch")
    _require(asset_approval.get("approval_status") == "USER_APPROVED",
             "Store PNG bytes have not been user-approved")
    _require(asset_approval.get("source_sha") == SOURCE_SHA
             and asset_approval.get("request_id") == REQUEST_ID,
             "Store asset approval is bound to a different source/request")
    _require(type(asset_approval.get("approved_by")) is str
             and len(asset_approval["approved_by"].strip()) >= 3,
             "Store asset approver is missing")
    _require(type(asset_approval.get("approval_reference")) is str
             and asset_approval["approval_reference"].strip(),
             "Store asset approval reference is missing")
    assets = asset_approval.get("assets")
    _require(type(assets) is dict and set(assets) == set(EXPECTED_ASSETS),
             "all three official Store PNG approvals are required")
    resolved = {}
    for relative, dimensions in EXPECTED_ASSETS.items():
        record = assets.get(relative)
        _require(type(record) is dict and record.get("approved") is True,
                 "Store asset is not individually approved: " + relative)
        _require(record.get("path") == relative, "Store asset path mismatch: " + relative)
        _require(record.get("width") == dimensions[0] and record.get("height") == dimensions[1],
                 "approved Store asset dimensions mismatch: " + relative)
        _require(SHA256_RE.fullmatch(str(record.get("sha256", ""))) is not None,
                 "Store asset SHA256 is missing: " + relative)
        _require(CRC32_RE.fullmatch(str(record.get("crc32", ""))) is not None,
                 "Store asset CRC32 is missing: " + relative)
        path = _safe_child(asset_root, relative, "Store asset " + relative)
        data = path.read_bytes()
        width, height, crc = _png_details(data)
        _require((width, height) == dimensions, "actual Store PNG dimensions mismatch: " + relative)
        _require(record["width"] == width and record["height"] == height,
                 "approved dimensions differ from actual PNG: " + relative)
        _require(record["crc32"] == crc, "Store asset CRC32 mismatch: " + relative)
        _require(record["sha256"] == sha256_bytes(data), "Store asset SHA256 mismatch: " + relative)
        resolved[relative] = path
    return resolved


def _validate_manifest(manifest_path: str | Path, identity: dict, version: str) -> Path:
    path = _safe_file(manifest_path, "AppxManifest.xml")
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise BuildGateError("AppxManifest.xml is invalid") from exc
    _require(root.tag == f"{{{APPX_NS}}}Package", "AppxManifest root namespace mismatch")
    node = root.find(f"{{{APPX_NS}}}Identity")
    _require(node is not None, "AppxManifest Identity element is missing")
    _require(node.attrib.get("Name") == identity["package_identity_name"],
             "AppxManifest Identity Name mismatch")
    _require(node.attrib.get("Publisher") == identity["publisher"],
             "AppxManifest Publisher mismatch")
    _require(node.attrib.get("Version") == version, "AppxManifest Version mismatch")
    _require(node.attrib.get("ProcessorArchitecture") == "x64",
             "AppxManifest architecture must be x64")
    properties = root.find(f"{{{APPX_NS}}}Properties")
    _require(properties is not None, "AppxManifest Properties is missing")
    def child_text(parent, tag):
        child = parent.find(f"{{{APPX_NS}}}{tag}")
        return None if child is None else (child.text or "").strip()
    _require(child_text(properties, "DisplayName") == identity["reserved_display_name"],
             "AppxManifest DisplayName mismatch")
    _require(child_text(properties, "PublisherDisplayName") == identity["publisher_display_name"],
             "AppxManifest PublisherDisplayName mismatch")
    _require(child_text(properties, "Logo") == "Assets/StoreLogo.png",
             "AppxManifest StoreLogo mapping mismatch")
    app = root.find(f".//{{{APPX_NS}}}Application")
    _require(app is not None and app.attrib.get("Id") == "PrismRoute3D",
             "AppxManifest Application identity mismatch")
    _require(app.attrib.get("Executable") == "VFS/ProgramFilesX64/PrismRoute3D/candidate.exe",
             "AppxManifest executable mapping mismatch")
    _require(app.attrib.get("EntryPoint") == "Windows.FullTrustApplication",
             "AppxManifest entry point mismatch")
    visual = app.find(f"{{{UAP_NS}}}VisualElements")
    _require(visual is not None, "AppxManifest VisualElements is missing")
    _require(visual.attrib.get("Square150x150Logo") == "Assets/Square150x150Logo.png",
             "AppxManifest 150x150 logo mapping mismatch")
    _require(visual.attrib.get("Square44x44Logo") == "Assets/Square44x44Logo.png",
             "AppxManifest 44x44 logo mapping mismatch")
    _require(visual.attrib.get("DisplayName") == identity["reserved_display_name"],
             "AppxManifest visual DisplayName mismatch")
    capabilities = root.find(f"{{{APPX_NS}}}Capabilities")
    _require(capabilities is not None, "AppxManifest Capabilities is missing")
    full_trust = capabilities.find(f"{{{RESCAP_NS}}}Capability")
    _require(full_trust is not None and full_trust.attrib.get("Name") == "runFullTrust",
             "AppxManifest runFullTrust capability is missing")
    return path


def _validate_makeappx(receipt: dict, makeappx_path: str | Path) -> Path:
    _require(type(receipt) is dict, "read-only MakeAppx capability receipt is missing")
    path = _safe_file(makeappx_path, "MakeAppx.exe")
    _require(os.path.normcase(os.path.abspath(str(receipt.get("path", ""))))
             == os.path.normcase(os.path.abspath(str(path))),
             "MakeAppx receipt path mismatch")
    _require(receipt.get("file_version") == MAKEAPPX_FILE_VERSION,
             "MakeAppx file version changed; re-audit required")
    _require(receipt.get("sha256") == MAKEAPPX_SHA256
             and sha256_file(path) == MAKEAPPX_SHA256,
             "MakeAppx SHA256 mismatch; re-audit required")
    _require(receipt.get("authenticode_status") == "Valid"
             and "Microsoft Corporation" in str(receipt.get("signer_subject", "")),
             "MakeAppx Authenticode signer is not verified Microsoft")
    _require(receipt.get("help_probe_invoked") is True
             and receipt.get("help_probe_contains_pack_usage") is True,
             "MakeAppx read-only help probe is missing")
    _require(receipt.get("makeappx_pack_invoked") is False
             and receipt.get("product_msix_created") is False,
             "MakeAppx capability receipt must precede product packaging")
    return path


def validate_build_inputs(
    *,
    handoff: dict,
    identity_return: dict,
    identity_raw: bytes,
    version_return: dict,
    package_binding: dict,
    asset_approval: dict,
    asset_root: str | Path,
    manifest_path: str | Path,
    exe_path: str | Path,
    pck_path: str | Path,
    makeappx_receipt: dict,
    makeappx_path: str | Path,
) -> dict:
    """Validate every prerequisite without invoking MakeAppx."""
    try:
        validate_current_handoff(handoff)
    except (ValueError, TypeError, KeyError) as exc:
        raise BuildGateError("current-source handoff validation failed") from exc
    identity = _validate_identity(identity_return)
    version = _validate_version_return(version_return, identity_return, identity_raw, identity)
    _validate_binding(package_binding, identity, version)
    exe = _safe_file(exe_path, "candidate.exe")
    pck = _safe_file(pck_path, "candidate.pck")
    _require(exe.stat().st_size == EXPECTED_EXE_SIZE
             and sha256_file(exe) == EXE_SHA256,
             "candidate.exe size or SHA256 drift")
    _require(pck.stat().st_size == EXPECTED_PCK_SIZE
             and sha256_file(pck) == PCK_SHA256,
             "candidate.pck size or SHA256 drift")
    assets = _validate_assets(asset_approval, asset_root)
    manifest = _validate_manifest(manifest_path, identity, version)
    makeappx = _validate_makeappx(makeappx_receipt, makeappx_path)
    return {
        "status": "ALL_PRODUCT_MSIX_BUILD_GATES_VALIDATED_NO_PACKAGE_CREATED",
        "source_sha": SOURCE_SHA,
        "request_id": REQUEST_ID,
        "factory_artifact_id": FACTORY_ARTIFACT_ID,
        "registration_type": REGISTRATION_TYPE,
        "package_version": version,
        "identity_rebind": "VERIFIED_CURRENT_SOURCE_CAS",
        "official_store_assets": "USER_APPROVED_AND_HASH_VERIFIED",
        "exe_sha256": EXE_SHA256,
        "pck_sha256": PCK_SHA256,
        "makeappx_sha256": MAKEAPPX_SHA256,
        "manifest": str(manifest),
        "assets": {key: str(value) for key, value in assets.items()},
        "product_msix_created": False,
        "product_msix_signed": False,
        "store_submission_allowed": False,
        "physical_qa": "DEFERRED_LOCAL_GATE",
    }


def extract_factory_payload_from_custody(
    custody_zip: str | Path,
    output_dir: str | Path,
) -> dict:
    """Recover the original Factory ZIP from QA custody and verify every byte."""
    custody = _safe_file(custody_zip, "QA custody artifact ZIP")
    _require(custody.stat().st_size == EXPECTED_CUSTODY_SIZE,
             "QA custody artifact size mismatch")
    _require(sha256_file(custody) == QA_CUSTODY_ARTIFACT_SHA256,
             "QA custody artifact SHA256 mismatch")
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    nested = None
    try:
        with zipfile.ZipFile(custody, "r") as outer:
            for info in outer.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".zip"):
                    continue
                candidate = outer.read(info)
                if sha256_bytes(candidate) == FACTORY_ZIP_SHA256:
                    nested = destination / "factory-export-original.zip"
                    nested.write_bytes(candidate)
                    break
    except (OSError, zipfile.BadZipFile) as exc:
        raise BuildGateError("QA custody artifact ZIP is unreadable") from exc
    _require(nested is not None, "original exact Factory ZIP not found inside QA custody")
    _require(nested.stat().st_size == 37795977
             and sha256_file(nested) == FACTORY_ZIP_SHA256,
             "recovered Factory ZIP size or SHA256 mismatch")
    extracted = destination / "factory-payload"
    extracted.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(nested, "r") as archive:
            names = [info.filename for info in archive.infolist() if not info.is_dir()]
            _require(set(names) == {"candidate.exe", "candidate.pck", "export-evidence.json"},
                     "Factory ZIP member set mismatch")
            for name, size, digest in (
                ("candidate.exe", EXPECTED_EXE_SIZE, EXE_SHA256),
                ("candidate.pck", EXPECTED_PCK_SIZE, PCK_SHA256),
                ("export-evidence.json", 680,
                 "442d2c9070e017adf1c0ceaa96ba607f470c0f147176671f8a844122aca4d5bd"),
            ):
                data = archive.read(name)
                _require(len(data) == size and sha256_bytes(data) == digest,
                         "Factory ZIP member bytes mismatch: " + name)
                (extracted / name).write_bytes(data)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise BuildGateError("recovered Factory ZIP is invalid") from exc
    return {
        "factory_zip": str(nested),
        "candidate_exe": str(extracted / "candidate.exe"),
        "candidate_pck": str(extracted / "candidate.pck"),
        "export_manifest": str(extracted / "export-evidence.json"),
        "factory_artifact_id": FACTORY_ARTIFACT_ID,
        "source_sha": SOURCE_SHA,
        "request_id": REQUEST_ID,
        "factory_zip_sha256": FACTORY_ZIP_SHA256,
        "exe_sha256": EXE_SHA256,
        "pck_sha256": PCK_SHA256,
    }


def _verify_unsigned_msix(path: Path, validated: dict) -> None:
    required = {
        "AppxManifest.xml": validated["manifest"],
        "VFS/ProgramFilesX64/PrismRoute3D/candidate.exe": None,
        "VFS/ProgramFilesX64/PrismRoute3D/candidate.pck": None,
        **{key: None for key in EXPECTED_ASSETS},
    }
    try:
        with zipfile.ZipFile(path, "r") as package:
            _require(package.testzip() is None, "unsigned MSIX ZIP integrity check failed")
            names = set(package.namelist())
            _require(set(required).issubset(names), "unsigned MSIX is missing required members")
            expected_hashes = {
                "VFS/ProgramFilesX64/PrismRoute3D/candidate.exe": EXE_SHA256,
                "VFS/ProgramFilesX64/PrismRoute3D/candidate.pck": PCK_SHA256,
            }
            for asset_path, source_path in validated["assets"].items():
                expected_hashes[asset_path] = sha256_file(source_path)
            for member, expected in expected_hashes.items():
                _require(sha256_bytes(package.read(member)) == expected,
                         "unsigned MSIX payload drift: " + member)
            _require(sha256_bytes(package.read("AppxManifest.xml"))
                     == sha256_file(validated["manifest"]),
                     "unsigned MSIX AppxManifest drift")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise BuildGateError("unsigned MSIX output is invalid") from exc


def build_unsigned_msix(
    *,
    validated_inputs: dict,
    exe_path: str | Path,
    pck_path: str | Path,
    asset_root: str | Path,
    makeappx_path: str | Path,
    output_path: str | Path,
    environment: dict | None = None,
) -> dict:
    """Invoke MakeAppx only after all gates and explicit environment approval."""
    env = os.environ if environment is None else environment
    _require(env.get("PRISM_MSIX_BUILD_APPROVED") == "true",
             "real product build requires protected PRISM_MSIX_BUILD_APPROVED=true")
    _require(validated_inputs.get("status") == "ALL_PRODUCT_MSIX_BUILD_GATES_VALIDATED_NO_PACKAGE_CREATED",
             "validated build-gate receipt is missing")
    output = Path(output_path).resolve()
    _require(not output.exists(), "refusing to overwrite an existing MSIX")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prism-route-3d-msix-") as temporary:
        stage = Path(temporary)
        shutil.copyfile(validated_inputs["manifest"], stage / "AppxManifest.xml")
        payload = stage / "VFS" / "ProgramFilesX64" / "PrismRoute3D"
        payload.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_safe_file(exe_path, "candidate.exe"), payload / "candidate.exe")
        shutil.copyfile(_safe_file(pck_path, "candidate.pck"), payload / "candidate.pck")
        for relative, source in validated_inputs["assets"].items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        command = [
            str(_safe_file(makeappx_path, "MakeAppx.exe")),
            "pack", "/d", str(stage), "/p", str(output), "/v",
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise BuildGateError("MakeAppx pack failed; no signing or Store action was attempted") from exc
    _verify_unsigned_msix(output, validated_inputs)
    return {
        "status": "UNSIGNED_PRODUCT_MSIX_CREATED_PENDING_SEPARATE_REVIEW",
        "source_sha": SOURCE_SHA,
        "request_id": REQUEST_ID,
        "package_version": validated_inputs["package_version"],
        "output_path": str(output),
        "output_sha256": sha256_file(output),
        "product_msix_created": True,
        "product_msix_signed": False,
        "identity_cas_invoked": False,
        "package_version_written": False,
        "partner_center_written": False,
        "store_submission_allowed": False,
        "physical_qa": "DEFERRED_LOCAL_GATE",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", default="handoffs/prism-route-3d-current-source-package-readiness-20261128.json")
    parser.add_argument("--identity-return", required=True)
    parser.add_argument("--version-return", required=True)
    parser.add_argument("--package-binding", required=True)
    parser.add_argument("--asset-approval", required=True)
    parser.add_argument("--asset-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--pck", required=True)
    parser.add_argument("--makeappx-receipt", required=True)
    parser.add_argument("--makeappx", default=MAKEAPPX_PATH)
    parser.add_argument("--output", default="dist/prism-route-3d-unsigned.msix")
    parser.add_argument("--build", action="store_true",
                        help="explicitly invoke MakeAppx after every gate passes")
    args = parser.parse_args(argv)
    try:
        handoff, _ = load_json(args.handoff)
        identity_return, identity_raw = load_json(args.identity_return)
        version_return, _ = load_json(args.version_return)
        package_binding, _ = load_json(args.package_binding)
        asset_approval, _ = load_json(args.asset_approval)
        makeappx_receipt, _ = load_json(args.makeappx_receipt)
        validated = validate_build_inputs(
            handoff=handoff,
            identity_return=identity_return,
            identity_raw=identity_raw,
            version_return=version_return,
            package_binding=package_binding,
            asset_approval=asset_approval,
            asset_root=args.asset_root,
            manifest_path=args.manifest,
            exe_path=args.exe,
            pck_path=args.pck,
            makeappx_receipt=makeappx_receipt,
            makeappx_path=args.makeappx,
        )
        result = validated
        if args.build:
            result = build_unsigned_msix(
                validated_inputs=validated,
                exe_path=args.exe,
                pck_path=args.pck,
                asset_root=args.asset_root,
                makeappx_path=args.makeappx,
                output_path=args.output,
            )
        else:
            result = dict(validated)
            result["status"] = "ALL_GATES_VALIDATED_NO_PRODUCT_MSIX_CREATED"
    except (BuildGateError, OSError, ValueError, TypeError, KeyError) as exc:
        result = {
            "status": "HOLD_PRODUCT_MSIX_NOT_CREATED",
            "reason": str(exc)[:240],
            "source_sha": SOURCE_SHA,
            "request_id": REQUEST_ID,
            "product_msix_created": False,
            "product_msix_signed": False,
            "identity_cas_invoked": False,
            "package_version_written": False,
            "partner_center_written": False,
            "store_submission_allowed": False,
            "physical_qa": "DEFERRED_LOCAL_GATE",
        }
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
