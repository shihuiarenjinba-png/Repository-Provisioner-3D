"""Safe Windows package/Store Identity round-trip for one allowlisted Factory.

All three Provisioners use this implementation; config.json fixes the product
type and return route. It does not create repositories, reserve Store names,
submit packages, or write to main/release.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable
from urllib.parse import quote, urlparse
import zipfile
import xml.etree.ElementTree as ET

SCHEMA_VERSION = "1.0"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SLUG = re.compile(r"^[a-z][a-z0-9-]{3,39}$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$")
VERSION = re.compile(r"^\d{1,5}(?:\.\d{1,5}){3}$")
STORE_ID = re.compile(r"^[A-Za-z0-9]{8,32}$")
IDENTITY_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,49}$")
PACKAGE_FAMILY_NAME = re.compile(r"^[A-Za-z0-9._-]+_[a-z0-9]{13}$")
PACKAGE_SID = re.compile(r"^S-1-15-2(?:-\d+){7}$")
ALLOWED_ACTIONS = {"BUILD_WINDOWS", "INSPECT_PACKAGE", "LOOKUP_OFFICIAL_IDENTITY", "PROPOSE_GITHUB_RETURN"}
FINAL_STATUSES = {"COMPLETED", "DRY_RUN", "CONFLICT"}
TRANSIENT_HTTP = {429, 500, 502, 503, 504}


def valid_work_branch(value: Any) -> bool:
    if not isinstance(value, str) or not 7 <= len(value) <= 240 or not value.startswith("codex/"):
        return False
    if not re.fullmatch(r"codex/[A-Za-z0-9._/-]+", value):
        return False
    if ".." in value or "//" in value or "@{" in value or value.endswith(("/", ".")):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in value.split("/"))


class ProvisionerError(Exception):
    status = "FAILED"
    next_stage = "FIX_INPUT_OR_IMPLEMENTATION"


class HoldError(ProvisionerError):
    status = "HOLD"
    next_stage = "RESOLVE_HOLD"


class ConflictError(ProvisionerError):
    status = "CONFLICT"
    next_stage = "RECONCILE_CONFLICT"


class RetryableError(ProvisionerError):
    status = "RETRYABLE_FAILURE"
    next_stage = "RETRY_WITH_SAME_REQUEST"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def redact(text: str) -> str:
    result = text
    result = re.sub(r"(?i)(authorization\s*:\s*(?:bearer|token)\s+)[^\s]+", r"\1[REDACTED]", result)
    result = re.sub(r"(?i)((?:token|secret|password|client_secret)\s*[=:]\s*)[^\s,;]+", r"\1[REDACTED]", result)
    result = re.sub(r"\bgh[opsu]_[A-Za-z0-9_]{20,}\b", "[REDACTED]", result)
    return result[:4000]


def load_json(path: Path, max_bytes: int = 65_536) -> dict[str, Any]:
    if not path.is_file():
        raise HoldError(f"JSON file not found: {path}")
    if path.stat().st_size > max_bytes:
        raise HoldError(f"JSON file exceeds {max_bytes} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HoldError(f"Invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise HoldError("JSON root must be an object")
    return value


@dataclass(frozen=True)
class ProductConfig:
    product_type: str
    source_factory: str
    source_repository: str
    source_branch: str
    target_owner: str
    build_kind: str
    output_patterns: tuple[str, ...]

    @classmethod
    def load(cls, path: Path) -> "ProductConfig":
        raw = load_json(path)
        required = {"product_type", "source_factory", "source_repository", "source_branch", "target_owner", "build_kind", "output_patterns"}
        if set(raw) != required:
            raise RuntimeError("config.json has missing or unknown fields")
        if raw["build_kind"] not in {"WINDOWS", "GODOT_WINDOWS"}:
            raise RuntimeError("unsupported build_kind")
        return cls(
            product_type=str(raw["product_type"]), source_factory=str(raw["source_factory"]),
            source_repository=str(raw["source_repository"]), source_branch=str(raw["source_branch"]),
            target_owner=str(raw["target_owner"]), build_kind=str(raw["build_kind"]),
            output_patterns=tuple(str(x) for x in raw["output_patterns"]),
        )


@dataclass(frozen=True)
class Job:
    schema_version: str
    request_id: str
    product_type: str
    source_factory: str
    source_repository: str
    source_branch: str
    source_sha: str
    slug: str
    display_name: str
    target_owner: str
    dry_run: bool
    requested_actions: tuple[str, ...]

    @classmethod
    def validate(cls, raw: dict[str, Any], config: ProductConfig) -> "Job":
        required = {"schema_version", "request_id", "product_type", "source_factory", "source_repository", "source_branch", "source_sha", "slug", "display_name", "target_owner", "dry_run", "requested_actions"}
        missing, unknown = required - set(raw), set(raw) - required
        if missing:
            raise HoldError("Missing required fields: " + ", ".join(sorted(missing)))
        if unknown:
            raise HoldError("Unknown input fields: " + ", ".join(sorted(unknown)))
        if raw["schema_version"] != SCHEMA_VERSION:
            raise HoldError("Unsupported schema_version")
        if not isinstance(raw["request_id"], str) or not REQUEST_ID.fullmatch(raw["request_id"]):
            raise HoldError("Invalid request_id")
        if raw["product_type"] != config.product_type:
            raise HoldError("Product type belongs to a different Provisioner")
        exact = {"source_factory": config.source_factory, "source_repository": config.source_repository,
                 "target_owner": config.target_owner}
        for field, expected in exact.items():
            if raw[field] != expected:
                raise HoldError(f"{field} is not the configured allowlisted value")
        if not valid_work_branch(raw["source_branch"]):
            raise HoldError("source_branch must be a safe codex/* work branch")
        if not isinstance(raw["source_sha"], str) or not SHA40.fullmatch(raw["source_sha"]) or set(raw["source_sha"]) == {"0"}:
            raise HoldError("source_sha must be an exact non-placeholder lowercase Git SHA")
        if not isinstance(raw["slug"], str) or not SLUG.fullmatch(raw["slug"]):
            raise HoldError("Invalid product slug")
        name = raw["display_name"]
        if not isinstance(name, str) or not 1 <= len(name) <= 100 or any(c in name for c in "\r\n\0"):
            raise HoldError("Invalid display_name")
        if type(raw["dry_run"]) is not bool:
            raise HoldError("dry_run must be boolean")
        actions = raw["requested_actions"]
        if not isinstance(actions, list) or not actions or not all(isinstance(x, str) for x in actions):
            raise HoldError("requested_actions must be a non-empty string array")
        if len(actions) != len(set(actions)) or set(actions) - ALLOWED_ACTIONS:
            raise HoldError("requested_actions contains duplicate or unsupported actions")
        return cls(**{**raw, "requested_actions": tuple(actions)})

    def fingerprint(self) -> str:
        return canonical_hash(asdict(self))


class RequestLock:
    def __init__(self, path: Path, stale_seconds: int = 21_600):
        self.path, self.stale_seconds, self.acquired = path, stale_seconds, False

    def __enter__(self) -> "RequestLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump({"pid": os.getpid(), "created_at": utc_now()}, handle)
                self.acquired = True
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:
                    age = 0
                if age > self.stale_seconds:
                    self.path.unlink(missing_ok=True)
                    continue
                raise ConflictError("The same request_id is already running")
        raise ConflictError("Could not acquire request lock")

    def __exit__(self, *_: object) -> None:
        if self.acquired:
            self.path.unlink(missing_ok=True)


class Ledger:
    def __init__(self, state_dir: Path):
        self.records, self.locks = state_dir / "records", state_dir / "locks"
        self.records.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(request_id: str) -> str:
        return hashlib.sha256(request_id.encode("utf-8")).hexdigest()

    def path(self, request_id: str) -> Path:
        return self.records / f"{self.key(request_id)}.json"

    def lock(self, request_id: str) -> RequestLock:
        return RequestLock(self.locks / f"{self.key(request_id)}.lock")

    def read(self, request_id: str) -> dict[str, Any] | None:
        path = self.path(request_id)
        return load_json(path, 262_144) if path.exists() else None

    def write(self, request_id: str, value: dict[str, Any]) -> None:
        path = self.path(request_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class SourceManager:
    def acquire(self, job: Job, destination: Path) -> Path:
        if destination.exists():
            if not (destination / ".git").exists():
                raise HoldError("Existing source workspace is not a Git checkout")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._run(["git", "clone", "--filter=blob:none", "--no-checkout",
                       f"https://github.com/{job.source_repository}.git", str(destination)], 180)
        remote = self._run(["git", "ls-remote", "origin", f"refs/heads/{job.source_branch}"], 60, destination).strip().split()
        if not remote or remote[0] != job.source_sha:
            raise ConflictError("Factory work branch HEAD does not match source_sha")
        self._run(["git", "fetch", "--depth=1", "origin", job.source_sha], 180, destination)
        self._run(["git", "checkout", "--detach", job.source_sha], 60, destination)
        if self._run(["git", "rev-parse", "HEAD"], 30, destination).strip() != job.source_sha:
            raise ConflictError("Detached checkout does not match source_sha")
        return destination

    @staticmethod
    def _run(command: list[str], timeout: int, cwd: Path | None = None) -> str:
        try:
            result = subprocess.run(command, cwd=cwd, text=True, encoding="utf-8", capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RetryableError("Git operation timed out; re-query before retry") from exc
        if result.returncode:
            detail = redact(result.stderr or result.stdout)
            if any(x in detail.lower() for x in ("timed out", "could not resolve", "connection")):
                raise RetryableError("Temporary GitHub transport failure")
            if any(x in detail.lower() for x in ("authentication", "permission", "403")):
                raise HoldError("GitHub authentication or read permission is insufficient")
            raise HoldError("Git source acquisition failed: " + detail[:300])
        return result.stdout


class PackageBuilder:
    WINDOWS_ENTRYPOINTS = ("build-windows-store-msix.cmd", "build-windows-desktop.cmd", "scripts/build-windows.ps1")

    def build(self, job: Job, source: Path, output_dir: Path, config: ProductConfig) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        if config.build_kind == "GODOT_WINDOWS":
            # The Factory stores each game under products/<slug>, not at repo root.
            # Never export another product or select an unrelated EXE as evidence.
            project_root = source / "products" / job.slug
            if not project_root.is_dir() or project_root.is_symlink():
                raise HoldError("Pinned 3D product directory is missing or symlinked")
            if not project_root.resolve().is_relative_to(source.resolve()):
                raise HoldError("3D product path escapes the pinned Factory checkout")
            self._build_godot(project_root, output_dir)
            # Only the exact export target is eligible for 3D pre-MSIX evidence.
            # A reused output directory may contain unrelated/stale executables.
            candidates = [output_dir / "candidate.exe"]
        else:
            before = {p.resolve(): (p.stat().st_mtime_ns, p.stat().st_size)
                      for p in self._candidates(source, config) if p.is_file()}
            self._build_windows(source)
            candidates = [p for p in self._candidates(source, config) if p.is_file() and
                          before.get(p.resolve()) != (p.stat().st_mtime_ns, p.stat().st_size)]
            candidates.extend(self._candidates(output_dir, config))
        unique = sorted({p.resolve() for p in candidates if p.is_file()}, key=lambda p: p.stat().st_mtime)
        if not unique:
            raise HoldError("Build completed without a configured EXE/MSIX candidate")
        return unique[-1]

    @staticmethod
    def _candidates(root: Path, config: ProductConfig) -> list[Path]:
        result: list[Path] = []
        for pattern in config.output_patterns:
            result.extend(root.glob(pattern))
        return result

    def _build_windows(self, source: Path) -> None:
        for relative in self.WINDOWS_ENTRYPOINTS:
            path = source / relative
            if not path.is_file():
                continue
            powershell = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
            command = ([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)]
                       if path.suffix.lower() == ".ps1" else ["cmd", "/d", "/c", str(path)])
            self._run(command, source, 1800)
            return
        raise HoldError("No allowlisted Windows build entrypoint exists in the pinned source")

    def _build_godot(self, source: Path, output_dir: Path) -> None:
        # SourceManager may return a relative work path. Godot resolves --path
        # relative to the subprocess cwd, so passing that relative path twice
        # incorrectly points outside the project. Pin both to absolute paths.
        source = source.resolve(strict=True)
        output_dir = output_dir.resolve(strict=True)
        project, presets = source / "project.godot", source / "export_presets.cfg"
        if project.is_symlink() or presets.is_symlink():
            raise HoldError("Godot project or export preset is symlinked")
        if not project.is_file() or not presets.is_file():
            raise HoldError("Godot project.godot/export_presets.cfg is incomplete")
        if project.stat().st_size > 128_000 or b"run/main_scene" not in project.read_bytes():
            raise HoldError("Godot project failed dedicated source QA")
        huge = next((p for p in source.rglob("*") if p.is_file() and p.stat().st_size > 2_000_000_000), None)
        if huge:
            raise HoldError("Godot source contains a file larger than the local QA limit")
        executable = os.environ.get("GODOT_EXE") or shutil.which("godot") or shutil.which("godot4")
        if not executable:
            raise HoldError("Godot executable is not configured (GODOT_EXE)")
        target = output_dir / "candidate.exe"
        # Retries reuse the same request workspace. Never let an old EXE/PCK
        # satisfy a new export that returned success without writing payloads.
        for stale in (target, target.with_suffix(".pck")):
            if stale.is_symlink() or stale.is_file():
                stale.unlink()
            elif stale.exists():
                raise HoldError("Godot export target is not a regular file")
        self._run([executable, "--headless", "--path", str(source), "--export-release", "Windows Desktop", str(target)], source, 1800)
        if target.is_symlink() or not target.is_file() or target.stat().st_size == 0:
            raise HoldError("Godot Windows export produced no nonempty executable")
        # Validate the PE32+ x64 structure before trusting the Godot export.
        # This is static byte QA, not Windows launch/GPU/GUI verification.
        _validate_godot_windows_pe_x64(target)
        # Godot's Windows Desktop export may place game data in a separate
        # candidate.pck. Accepting only candidate.exe silently loses resources
        # when binary_format/embed_pck=false.
        try:
            preset_text = presets.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            raise HoldError("Cannot read Godot Windows export preset") from exc
        if re.search(r"(?m)^\s*binary_format/embed_pck\s*=\s*false\s*$", preset_text):
            pck = target.with_suffix(".pck")
            if pck.is_symlink() or not pck.is_file() or pck.stat().st_size < 4:
                raise HoldError("Godot Windows export omitted required candidate.pck payload")
            with pck.open("rb") as handle:
                if handle.read(4) != b"GDPC":
                    raise HoldError("Godot Windows export PCK has invalid GDPC header")

    @staticmethod
    def _run(command: list[str], cwd: Path, timeout: int) -> None:
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RetryableError("Package build timed out") from exc
        if result.returncode:
            raise HoldError("Package build failed: " + redact(result.stderr or result.stdout)[:500])


class _PackageVersion(ctypes.Union):
    _fields_ = [("version", ctypes.c_uint64)]


class _PackageId(ctypes.Structure):
    _fields_ = [
        ("reserved", ctypes.c_uint32),
        ("processorArchitecture", ctypes.c_uint32),
        ("version", _PackageVersion),
        ("name", wintypes.LPWSTR),
        ("publisher", wintypes.LPWSTR),
        ("resourceId", wintypes.LPWSTR),
        ("publisherId", wintypes.LPWSTR),
    ]


def _package_family_name(name: str, publisher: str) -> str | None:
    """Use the Windows AppModel API; PFN/PublisherId are opaque values."""
    if os.name != "nt":
        return None
    package_id = _PackageId()
    package_id.name = name
    package_id.publisher = publisher
    length = ctypes.c_uint32(256)
    buffer = ctypes.create_unicode_buffer(length.value)
    rc = ctypes.windll.kernel32.PackageFamilyNameFromId(ctypes.byref(package_id), ctypes.byref(length), buffer)
    return buffer.value if rc == 0 else None


def _windows_package_sid(package_family_name: str) -> str | None:
    if os.name != "nt":
        return None
    sid, text = ctypes.c_void_p(), wintypes.LPWSTR()
    if ctypes.windll.userenv.DeriveAppContainerSidFromAppContainerName(package_family_name, ctypes.byref(sid)) != 0:
        return None
    try:
        if not ctypes.windll.advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            return None
        return text.value
    finally:
        if text:
            ctypes.windll.kernel32.LocalFree(text)
        ctypes.windll.advapi32.FreeSid(sid)


def signature_status(path: Path) -> str:
    if os.name != "nt":
        return "UNAVAILABLE_NON_WINDOWS"
    escaped = str(path).replace("'", "''")
    powershell = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
    command = [powershell, "-NoProfile", "-NonInteractive", "-Command",
               f"(Get-AuthenticodeSignature -LiteralPath '{escaped}').Status.ToString()"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "INSPECTION_FAILED"
    return result.stdout.strip().upper() if result.returncode == 0 and result.stdout.strip() else "INSPECTION_FAILED"


def _validate_godot_windows_pe_x64(path: Path) -> None:
    """Reject MZ-only, truncated, non-x64 or non-PE32+ Godot export files.

    Bounds and COFF/optional-header checks are static format checks only.
    A valid PE header is not evidence of a runnable or safe product.
    """
    size = path.stat().st_size
    with path.open("rb") as handle:
        dos = handle.read(64)
        if dos[:2] != b"MZ":
            raise HoldError("Godot Windows export EXE is missing the MZ header")
        if len(dos) < 64:
            raise HoldError("Godot Windows export has a truncated DOS header")
        pe_offset = int.from_bytes(dos[0x3c:0x40], "little")
        if pe_offset < 64 or pe_offset > 1024 * 1024 or pe_offset + 26 > size:
            raise HoldError("Godot Windows export has an invalid PE offset")
        handle.seek(pe_offset)
        pe = handle.read(26)
        if pe[:4] != b"PE\x00\x00":
            raise HoldError("Godot Windows export has an invalid PE signature")
        machine = int.from_bytes(pe[4:6], "little")
        sections = int.from_bytes(pe[6:8], "little")
        optional_size = int.from_bytes(pe[20:22], "little")
        if machine != 0x8664:
            raise HoldError("Godot Windows export PE machine is not x64")
        if not 1 <= sections <= 96:
            raise HoldError("Godot Windows export has invalid PE section count")
        if optional_size < 0x70 or pe[24:26] != b"\x0b\x02":
            raise HoldError("Godot Windows export is not PE32+")
        if pe_offset + 24 + optional_size + sections * 40 > size:
            raise HoldError("Godot Windows export has a truncated PE section table")
        # A valid COFF table is insufficient if its sections reference bytes
        # beyond the end of the file. Do not accept phantom raw payloads.
        section_table = pe_offset + 24 + optional_size
        handle.seek(section_table)
        for _ in range(sections):
            section = handle.read(40)
            if len(section) != 40:
                raise HoldError("Godot Windows export has a truncated PE section")
            raw_size = int.from_bytes(section[16:20], "little")
            raw_pointer = int.from_bytes(section[20:24], "little")
            if raw_size and (not raw_pointer or raw_pointer > size
                             or raw_size > size - raw_pointer):
                raise HoldError("Godot Windows export PE section raw data is outside the file")


def inspect_package(path: Path, *, godot_export: bool = False) -> dict[str, Any]:
    if not path.is_file():
        raise HoldError("Package artifact does not exist")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    result: dict[str, Any] = {
        "status": "INSPECTED", "path": str(path.resolve()), "kind": path.suffix.lower().lstrip("."),
        "sha256": digest.hexdigest(), "size_bytes": path.stat().st_size,
        "signature_status": signature_status(path), "package_identity": None, "publisher": None,
        "version": None, "package_family_name": None, "package_sid": None,
    }
    if godot_export:
        if path.suffix.lower() != ".exe" or path.is_symlink():
            raise HoldError("Godot export evidence must be a regular Windows EXE")
        _validate_godot_windows_pe_x64(path)
        pck = path.with_suffix(".pck")
        if pck.is_symlink() or (pck.exists() and not pck.is_file()):
            raise HoldError("Godot external PCK evidence is not a regular file")
        pck_sha256, pck_size_bytes = None, None
        if pck.exists():
            digest_pck = hashlib.sha256()
            with pck.open("rb") as handle:
                header = handle.read(4)
                if header != b"GDPC":
                    raise HoldError("Godot external PCK has invalid GDPC header")
                digest_pck.update(header)
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest_pck.update(chunk)
            pck_sha256 = digest_pck.hexdigest()
            pck_size_bytes = pck.stat().st_size
        result["godot_export"] = {
            "exe_sha256": result["sha256"],
            "external_pck_sha256": pck_sha256,
            "external_pck_size_bytes": pck_size_bytes,
            "evidence_scope": "LOCAL_EXPORT_NOT_INDEPENDENT",
        }
    if path.suffix.lower() not in {".msix", ".appx"}:
        return result
    try:
        with zipfile.ZipFile(path) as archive:
            manifest_name = next((n for n in archive.namelist() if n.lower() == "appxmanifest.xml"), None)
            if manifest_name is None:
                raise HoldError("MSIX is missing AppxManifest.xml")
            raw = archive.read(manifest_name)
        root = ET.fromstring(raw)
        identity = next((element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Identity"), None)
        if identity is None:
            raise HoldError("MSIX manifest has no Identity element")
        name, publisher, version = (identity.attrib.get(key) for key in ("Name", "Publisher", "Version"))
        if not name or not publisher or not version:
            raise HoldError("MSIX Identity is incomplete")
        family = _package_family_name(name, publisher)
        result.update(package_identity=name, publisher=publisher, version=version,
                      package_family_name=family,
                      package_sid=_windows_package_sid(family) if family else None)
        return result
    except (zipfile.BadZipFile, ET.ParseError, KeyError) as exc:
        raise HoldError(f"Invalid MSIX package: {exc}") from exc


class OfficialIdentityProvider:
    """Read an operator export from a separately authenticated Partner Center session."""
    def __init__(self, evidence_path: Path | None):
        self.evidence_path = evidence_path

    def lookup(self, job: Job) -> dict[str, Any]:
        if self.evidence_path is None:
            raise HoldError("No authenticated Partner Center identity evidence was supplied")
        raw = load_json(self.evidence_path, 32_768)
        required = {"request_id", "product_type", "slug", "source_sha", "authenticated_account", "verified_at",
                    "official_evidence_url", "store_id", "name", "publisher", "version",
                    "package_family_name", "package_sid"}
        if set(raw) != required:
            raise HoldError("Official identity evidence has missing or unknown fields")
        exact = {"request_id": job.request_id, "product_type": job.product_type, "slug": job.slug, "source_sha": job.source_sha}
        if any(raw[key] != value for key, value in exact.items()):
            raise ConflictError("Official identity evidence belongs to another product/request/SHA")
        if not isinstance(raw["authenticated_account"], str) or not 3 <= len(raw["authenticated_account"]) <= 100:
            raise HoldError("Authenticated Partner Center account identifier is missing")
        url = urlparse(str(raw["official_evidence_url"]))
        if url.scheme != "https" or url.hostname not in {"partner.microsoft.com", "partnercenter.microsoft.com"} or url.username or url.password or url.fragment:
            raise HoldError("Official evidence URL is not a trusted Partner Center URL")
        if not isinstance(raw["store_id"], str) or not STORE_ID.fullmatch(raw["store_id"]):
            raise HoldError("Invalid official Store ID")
        if not isinstance(raw["name"], str) or not IDENTITY_NAME.fullmatch(raw["name"]):
            raise HoldError("Invalid official Identity Name")
        if not isinstance(raw["publisher"], str) or not raw["publisher"].startswith("CN=") or len(raw["publisher"]) > 512:
            raise HoldError("Invalid official Publisher")
        if not isinstance(raw["version"], str) or not VERSION.fullmatch(raw["version"]):
            raise HoldError("Invalid official version")
        pfn = raw["package_family_name"]
        sid = raw["package_sid"]
        if not isinstance(pfn, str) or not PACKAGE_FAMILY_NAME.fullmatch(pfn):
            raise HoldError("Invalid official Package Family Name")
        if not isinstance(sid, str) or not PACKAGE_SID.fullmatch(sid):
            raise HoldError("Invalid official Package SID")
        return raw


def compare_package_identity(package: dict[str, Any], official: dict[str, Any],
                             product_type: str) -> str:
    """Compare what the local package can prove before Factory MSIX rebuild.

    APP/GAME still require an MSIX/AppX identity match locally. GAME_3D first
    produces a real Godot Windows EXE/PCK payload; Store Identity is then
    returned to Factory, where the reviewed Identity is injected into the
    final MSIX. The EXE cannot contain a Store Package Identity, so requiring
    one here made the 3D conveyor impossible to complete.
    """
    kind = package.get("kind")
    if kind not in {"msix", "appx"}:
        if product_type == "GAME_3D" and kind == "exe":
            digest = package.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise HoldError("3D Windows export has no verified package SHA-256")
            return "DEFERRED_TO_FACTORY_MSIX"
        raise HoldError("Official Identity requires MSIX/AppX for this product type")
    checks = (("package_identity", "name"), ("publisher", "publisher"), ("version", "version"))
    if os.name == "nt" and (not package.get("package_family_name") or not package.get("package_sid")):
        raise HoldError("Windows package PFN or Package SID could not be collected")
    mismatches = [f"{left}!={right}" for left, right in checks if package.get(left) != official.get(right)]
    if package.get("package_family_name") and package.get("package_family_name") != official.get("package_family_name"):
        mismatches.append("package_family_name!=official")
    if package.get("package_sid") and package.get("package_sid") != official.get("package_sid"):
        mismatches.append("package_sid!=official")
    if mismatches:
        raise ConflictError("Package and official Identity mismatch: " + ", ".join(mismatches))
    return "MATCHED_LOCAL_MSIX"


def windows_all_auto_record(job: Job, official: dict[str, Any],
                            package: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "type": {"APP": "app", "GAME": "game", "GAME_3D": "3d-game"}[job.product_type],
        "request_id": job.request_id,
        "product_type": job.product_type,
        "source_factory": job.source_factory,
        "source_repository": job.source_repository,
        "source_branch": job.source_branch,
        "source_sha": job.source_sha,
        "slug": job.slug,
        "expected_head_sha": job.source_sha,
        "package_sha256": package["sha256"],
        "package_family_name": official["package_family_name"],
        "package_sid": official["package_sid"],
        "signature_status": package["signature_status"],
        "local_package_sha256": package["sha256"],
        "local_package_kind": package["kind"],
        "local_signature_status": package["signature_status"],
        "official_evidence_url": official["official_evidence_url"],
        "operator_verified": True,
        "verified_by": official["authenticated_account"],
        "identity": {key: official[key] for key in
                     ("store_id", "name", "publisher", "version",
                      "package_family_name", "package_sid")},
    }


class GitHubReturnClient:
    MUTATION = "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input:$input) { commit { oid url } } }"

    def __init__(self, api: Callable[..., Any] | None = None):
        self.api = api or self._gh_api

    def return_identity(self, job: Job, config: ProductConfig, official: dict[str, Any],
                        package: dict[str, Any], apply: bool) -> dict[str, Any]:
        target_path = f"products/{job.slug}/store/approved-identity.json"
        base = f"repos/{config.source_repository}/"
        proposal = {"status": "NOT_APPLIED", "repository": config.source_repository, "branch": job.source_branch,
                    "path": target_path, "commit_sha": None, "commit_url": None}
        if not apply:
            return proposal
        ref = self.api(base + "git/ref/heads/" + job.source_branch)
        if not isinstance(ref, dict) or ref.get("object", {}).get("sha") != job.source_sha:
            raise ConflictError("Factory HEAD changed before identity return")
        self._verify_product(base, job, config)
        existing = self.api(base + "contents/" + target_path + "?ref=" + quote(job.source_branch, safe=""), allow_missing=True)
        if existing is not None:
            if self._existing_matches(existing, official, job, package):
                # GitHub Contents API 'sha' is a *blob* SHA, not a commit SHA.
                # Recheck the branch because no atomic mutation guards this read.
                latest_ref = self.api(base + "git/ref/heads/" + job.source_branch)
                if (not isinstance(latest_ref, dict)
                        or latest_ref.get("object", {}).get("sha") != job.source_sha):
                    raise ConflictError("Factory HEAD changed while verifying existing identity")
                return {**proposal, "status": "EXISTING_VERIFIED", "commit_sha": job.source_sha}
            raise ConflictError("approved-identity.json already exists and will not be overwritten")
        approved = {
                    "reviewed": True, "source": "partner_center",
                    "request_id": job.request_id, "product_type": job.product_type,
                    "source_factory": job.source_factory, "source_repository": job.source_repository,
                    "source_branch": job.source_branch, "slug": job.slug,
                    "store_id": official["store_id"], "name": official["name"],
                    "publisher": official["publisher"], "version": official["version"],
                    "package_family_name": official["package_family_name"],
                    "package_sid": official["package_sid"],
                    "verified_by": official["authenticated_account"],
                    "evidence_url": official["official_evidence_url"],
                    "verified_source_sha": job.source_sha,
                    "source_sha": job.source_sha,
                    "expected_head_sha": job.source_sha,
                    "package_sha256": package["sha256"],
                    "signature_status": package["signature_status"],
                    "local_package_sha256": package["sha256"],
                    "local_package_kind": package["kind"],
                    "local_signature_status": package["signature_status"]}
        content = json.dumps(approved, ensure_ascii=False, indent=2) + "\n"
        body = {"query": self.MUTATION, "variables": {"input": {
            "branch": {"repositoryNameWithOwner": config.source_repository, "branchName": job.source_branch},
            "message": {"headline": "store: return verified Partner Center identity for " + job.slug},
            "expectedHeadOid": job.source_sha,
            "fileChanges": {"additions": [{"path": target_path,
                "contents": base64.b64encode(content.encode("utf-8")).decode("ascii")}]} }}}
        output = self.api("graphql", body=body)
        if output.get("errors"):
            raise ConflictError("GitHub rejected atomic identity return")
        commit = output.get("data", {}).get("createCommitOnBranch", {}).get("commit")
        if not isinstance(commit, dict) or not SHA40.fullmatch(str(commit.get("oid", ""))):
            raise RetryableError("GitHub returned no confirmed commit SHA; reconcile before retry")
        return {**proposal, "status": "APPLIED", "commit_sha": commit["oid"], "commit_url": commit.get("url")}

    def _verify_product(self, base: str, job: Job, config: ProductConfig) -> None:
        branch = quote(job.source_branch, safe="")
        if config.product_type == "GAME_3D":
            item = self.api(base + f"contents/products/{job.slug}/project.godot?ref=" + branch)
            if b"run/main_scene" not in self._decode_content(item, 128_000):
                raise ConflictError("Pinned 3D product project.godot is invalid")
            # A valid Store Identity is insufficient when the pinned Godot
            # product cannot be exported for Windows.
            preset_item = self.api(base + f"contents/products/{job.slug}/export_presets.cfg?ref=" + branch)
            preset_bytes = self._decode_content(preset_item, 128_000)
            try:
                preset_text = preset_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ConflictError("Pinned 3D Windows export preset is not UTF-8") from exc
            sections = re.split(r"(?m)^\[preset\.\d+\]\s*$", preset_text)
            valid_preset = any(
                re.search(r'(?m)^\s*platform\s*=\s*"Windows Desktop"\s*$', section)
                and re.search(r'(?m)^\s*name\s*=\s*"Windows Desktop"\s*$', section)
                for section in sections[1:]
            )
            if not valid_preset:
                raise ConflictError("Pinned 3D product has no valid Windows Desktop export preset")
        else:
            item = self.api(base + f"contents/products/{job.slug}/manifest.json?ref=" + branch)
            try:
                manifest = json.loads(self._decode_content(item, 16_000))
            except json.JSONDecodeError as exc:
                raise ConflictError("Factory product manifest is invalid JSON") from exc
            expected_kind = "app" if config.product_type == "APP" else "game"
            if not isinstance(manifest, dict) or manifest.get("slug") != job.slug or manifest.get("kind") != expected_kind:
                raise ConflictError("Factory product manifest slug/kind mismatch")

    @staticmethod
    def _decode_content(item: Any, limit: int) -> bytes:
        if not isinstance(item, dict) or item.get("encoding") != "base64":
            raise ConflictError("Factory product evidence is missing")
        try:
            raw = base64.b64decode(item.get("content", ""), validate=True)
        except Exception as exc:
            raise ConflictError("Factory product evidence is not valid base64") from exc
        if len(raw) > limit:
            raise ConflictError("Factory product evidence is oversized")
        return raw

    @staticmethod
    def _existing_matches(existing: dict[str, Any], official: dict[str, Any],
                          job: Job, package: dict[str, Any]) -> bool:
        if existing.get("encoding") != "base64":
            return False
        try:
            content = json.loads(base64.b64decode(existing["content"], validate=True))
        except Exception:
            return False
        # Never treat a matching Store ID alone as proof of operator review.
        # The whole manufacturing correlation key and local package provenance
        # must match before an existing identity record can be reused.
        expected = {
            "reviewed": True,
            "source": "partner_center",
            "request_id": job.request_id,
            "product_type": job.product_type,
            "source_factory": job.source_factory,
            "source_repository": job.source_repository,
            "source_branch": job.source_branch,
            "slug": job.slug,
            "verified_by": official.get("authenticated_account"),
            "evidence_url": official.get("official_evidence_url"),
            "verified_source_sha": job.source_sha,
            "source_sha": job.source_sha,
            "expected_head_sha": job.source_sha,
            "package_sha256": package.get("sha256"),
            "signature_status": package.get("signature_status"),
            "local_package_sha256": package.get("sha256"),
            "local_package_kind": package.get("kind"),
            "local_signature_status": package.get("signature_status"),
        }
        if any(content.get(key) != value for key, value in expected.items()):
            return False
        return all(content.get(key) == official.get(key) for key in
                   ("store_id", "name", "publisher", "version",
                    "package_family_name", "package_sid"))

    @staticmethod
    def _gh_api(endpoint: str, body: dict[str, Any] | None = None, allow_missing: bool = False) -> Any:
        command = ["gh", "api", endpoint]
        if body is not None:
            command += ["--input", "-"]
        try:
            result = subprocess.run(command, input=json.dumps(body) if body else None, capture_output=True,
                                    text=True, encoding="utf-8", timeout=45, check=False)
        except FileNotFoundError as exc:
            raise HoldError("GitHub CLI is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise RetryableError("GitHub API timed out; reconcile before retry") from exc
        if result.returncode:
            detail = result.stderr or result.stdout
            match = re.search(r"HTTP\s+(\d{3})", detail)
            status = int(match.group(1)) if match else None
            if allow_missing and status == 404:
                return None
            if status in TRANSIENT_HTTP:
                raise RetryableError(f"GitHub API temporary failure ({status})")
            if status in {401, 403} or "auth" in detail.lower():
                raise HoldError("GitHub authentication/contents:write permission is insufficient")
            if status in {404, 422}:
                raise ConflictError(f"GitHub target, validation, or conflict error ({status})")
            raise HoldError("GitHub API failed: " + redact(detail)[:300])
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RetryableError("GitHub API returned invalid JSON") from exc


class Provisioner:
    def __init__(self, config: ProductConfig, state_dir: Path, work_dir: Path,
                 source: SourceManager | None = None, builder: PackageBuilder | None = None,
                 identity: OfficialIdentityProvider | None = None, github: GitHubReturnClient | None = None,
                 factory_transport: Any | None = None):
        self.config = config
        self.ledger = Ledger(state_dir / config.product_type.lower())
        self.work_dir = work_dir / config.product_type.lower()
        self.source, self.builder = source or SourceManager(), builder or PackageBuilder()
        self.identity, self.github = identity or OfficialIdentityProvider(None), github or GitHubReturnClient()
        self.factory_transport = factory_transport

    def run(self, raw: dict[str, Any], apply: bool = False, *,
            factory_run_id: int | None = None, factory_artifact_id: int | None = None) -> dict[str, Any]:
        started = utc_now()
        try:
            job = Job.validate(raw, self.config)
        except ProvisionerError as exc:
            return self._error_response(raw, exc, started)
        try:
            with self.ledger.lock(job.request_id):
                previous = self.ledger.read(job.request_id)
                if previous and previous.get("fingerprint") != job.fingerprint():
                    return self._record_error(job, ConflictError("request_id was previously used for different input"), started, previous)
                if previous and previous.get("response", {}).get("status") in FINAL_STATUSES:
                    return {**previous["response"], "idempotent_replay": True}
                if job.dry_run:
                    response = self._base_response(job, "DRY_RUN", started)
                    response["next_stage"] = "SUBMIT_NON_DRY_RUN_AFTER_REVIEW"
                    self._save(job, response, {"stage": "DRY_RUN_VALIDATED"})
                    return response
                package: dict[str, Any] | None = None
                factory_evidence: dict[str, Any] | None = None
                try:
                    root = self.work_dir / hashlib.sha256(job.request_id.encode()).hexdigest()[:16]
                    source_dir = self.source.acquire(job, root / "source")
                    built_path = self.builder.build(job, source_dir, root / "artifacts", self.config)
                    package = inspect_package(
                        built_path,
                        godot_export=(job.product_type == "GAME_3D" and built_path.suffix.lower() == ".exe"),
                    )
                    if job.product_type == "GAME_3D" and package.get("kind") == "exe":
                        # Fail closed before official Identity: only authenticated
                        # GitHub run + artifact metadata may establish provenance.
                        if self.factory_transport is None:
                            from factory_export_transport import FactoryExportTransport
                            self.factory_transport = FactoryExportTransport()
                        factory_evidence = self.factory_transport.verify(
                            job, package, run_id=factory_run_id,
                            artifact_id=factory_artifact_id, work_root=root / "factory-evidence")
                    official = self.identity.lookup(job)
                    comparison = compare_package_identity(package, official, job.product_type)
                    contract = windows_all_auto_record(job, official, package)
                    returned = self.github.return_identity(job, self.config, official, package, apply=apply)
                    status = "COMPLETED" if returned["status"] in {"APPLIED", "EXISTING_VERIFIED"} else "HOLD"
                    response = self._base_response(job, status, started)
                    response.update(package=package, factory_export_evidence=factory_evidence, official_identity={
                        "status": "VERIFIED_OPERATOR_EXPORT",
                        "package_comparison": comparison,
                        **{k: official[k] for k in
                        ("store_id", "name", "publisher", "version",
                         "package_family_name", "package_sid",
                         "official_evidence_url", "verified_at")}},
                        windows_all_auto_record=contract, github_return=returned,
                        next_stage="GITHUB_REBUILD_MSIX" if status == "COMPLETED" else "APPLY_VERIFIED_GITHUB_RETURN")
                    if status == "HOLD":
                        response["errors"] = ["Identity verified locally but GitHub return was not applied; rerun with --apply after review"]
                    self._save(job, response, {"stage": returned["status"], "package_sha256": package["sha256"]})
                    return response
                except ProvisionerError as exc:
                    return self._record_error(job, exc, started, previous, package=package,
                                              factory_evidence=factory_evidence)
                except Exception as exc:
                    return self._record_error(job, ProvisionerError(f"Unexpected local failure: {type(exc).__name__}"), started, previous,
                                              package=package, factory_evidence=factory_evidence)
        except ProvisionerError as exc:
            return self._error_response(raw, exc, started)

    def _base_response(self, job: Job, status: str, started: str) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "request_id": job.request_id, "product_type": job.product_type,
                "status": status, "source_factory": job.source_factory,
                "source_repository": job.source_repository, "source_branch": job.source_branch,
                "source_sha": job.source_sha, "slug": job.slug, "started_at": started, "finished_at": utc_now(),
                "idempotent_replay": False,
                "package": {"status": "NOT_BUILT", "sha256": None, "path": None, "package_identity": None,
                            "publisher": None, "version": None, "package_family_name": None, "package_sid": None,
                            "signature_status": None},
                "official_identity": {"status": "UNVERIFIED", "store_id": None, "name": None, "publisher": None,
                                      "version": None, "package_family_name": None, "package_sid": None,
                                      "package_comparison": None, "official_evidence_url": None},
                "github_return": {"status": "NOT_APPLIED", "repository": self.config.source_repository,
                                  "branch": job.source_branch,
                                  "path": f"products/{job.slug}/store/approved-identity.json", "commit_sha": None},
                "factory_export_evidence": None,
                "windows_all_auto_record": None, "errors": [], "next_stage": None}

    def _error_response(self, raw: dict[str, Any], exc: ProvisionerError, started: str) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION,
                "request_id": raw.get("request_id") if isinstance(raw.get("request_id"), str) else None,
                "product_type": raw.get("product_type") if isinstance(raw.get("product_type"), str) else self.config.product_type,
                "status": exc.status, "source_factory": raw.get("source_factory"),
                "source_repository": raw.get("source_repository"), "source_branch": raw.get("source_branch"),
                "source_sha": raw.get("source_sha"), "slug": raw.get("slug"),
                "package": {"status": "NOT_BUILT", "sha256": None},
                "official_identity": {"status": "UNVERIFIED", "store_id": None},
                "github_return": {"status": "NOT_APPLIED", "commit_sha": None},
                "errors": [redact(str(exc))], "next_stage": exc.next_stage,
                "started_at": started, "finished_at": utc_now(), "idempotent_replay": False}

    def _record_error(self, job: Job, exc: ProvisionerError, started: str,
                      previous: dict[str, Any] | None,
                      package: dict[str, Any] | None = None,
                      factory_evidence: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self._base_response(job, exc.status, started)
        if package is not None:
            # Preserve local EXE/PCK byte evidence across an external Identity HOLD.
            # This is inspection evidence, never an accepted product or E2E receipt.
            response["package"] = package
        if factory_evidence is not None:
            response["factory_export_evidence"] = factory_evidence
        response["errors"], response["next_stage"] = [redact(str(exc))], exc.next_stage
        self._save(job, response, {"stage": exc.status}, attempts=int((previous or {}).get("attempts", 0)) + 1)
        return response

    def _save(self, job: Job, response: dict[str, Any], checkpoint: dict[str, Any], attempts: int = 1) -> None:
        self.ledger.write(job.request_id, {"request_id": job.request_id, "product_type": job.product_type,
                          "fingerprint": job.fingerprint(), "attempts": attempts, "updated_at": utc_now(),
                          "checkpoint": checkpoint, "response": response})


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build/inspect a pinned Factory product and return verified Store Identity")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--state-dir", type=Path, default=Path(".provisioner-state"))
    parser.add_argument("--work-dir", type=Path, default=Path(".provisioner-work"))
    parser.add_argument("--official-identity", type=Path,
                        help="Operator export from an authenticated Partner Center session; never source-controlled")
    parser.add_argument("--factory-run-id", type=int,
                        help="Authenticated Factory Godot export GitHub Actions run ID (3D EXE only)")
    parser.add_argument("--factory-artifact-id", type=int,
                        help="Authenticated Factory export GitHub artifact ID (3D EXE only)")
    parser.add_argument("--apply", action="store_true", help="Atomically write to the configured Factory work branch")
    args = parser.parse_args(argv)
    started = utc_now()
    try:
        config, raw = ProductConfig.load(args.config), load_json(args.input)
        result = Provisioner(config, args.state_dir, args.work_dir,
                             identity=OfficialIdentityProvider(args.official_identity)).run(
                                 raw, apply=args.apply, factory_run_id=args.factory_run_id,
                                 factory_artifact_id=args.factory_artifact_id)
    except ProvisionerError as exc:
        result = {"schema_version": SCHEMA_VERSION, "request_id": None, "product_type": None,
                  "status": exc.status, "errors": [redact(str(exc))], "started_at": started, "finished_at": utc_now()}
    except Exception as exc:
        result = {"schema_version": SCHEMA_VERSION, "request_id": None, "product_type": None,
                  "status": "FAILED", "errors": [f"Startup failure: {type(exc).__name__}"],
                  "started_at": started, "finished_at": utc_now()}
    write_json(args.output, result)
    print(json.dumps({"request_id": result.get("request_id"), "status": result["status"], "output": str(args.output)}, ensure_ascii=False))
    return 0 if result["status"] in {"COMPLETED", "DRY_RUN"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
