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
ALLOWED_ACTIONS = {"BUILD_WINDOWS", "INSPECT_PACKAGE", "LOOKUP_OFFICIAL_IDENTITY", "PROPOSE_GITHUB_RETURN"}
FINAL_STATUSES = {"COMPLETED", "DRY_RUN", "CONFLICT"}
TRANSIENT_HTTP = {429, 500, 502, 503, 504}


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
                 "source_branch": config.source_branch, "target_owner": config.target_owner}
        for field, expected in exact.items():
            if raw[field] != expected:
                raise HoldError(f"{field} is not the configured allowlisted value")
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
            for attempt in range(5):
                try:
                    os.replace(temporary, path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.025 * (2 ** attempt))
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
        before = {p.resolve(): (p.stat().st_mtime_ns, p.stat().st_size)
                  for p in self._candidates(source, config) if p.is_file()}
        if config.build_kind == "GODOT_WINDOWS":
            self._build_godot(source, output_dir)
        else:
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
            command = (["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)]
                       if path.suffix.lower() == ".ps1" else ["cmd", "/d", "/c", str(path)])
            self._run(command, source, 1800)
            return
        raise HoldError("No allowlisted Windows build entrypoint exists in the pinned source")

    def _build_godot(self, source: Path, output_dir: Path) -> None:
        project, presets = source / "project.godot", source / "export_presets.cfg"
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
        self._run([executable, "--headless", "--path", str(source), "--export-release", "Windows Desktop", str(target)], source, 1800)
        if not target.is_file():
            raise HoldError("Godot Windows export produced no executable")

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
    command = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
               f"(Get-AuthenticodeSignature -LiteralPath '{escaped}').Status.ToString()"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "INSPECTION_FAILED"
    return result.stdout.strip().upper() if result.returncode == 0 and result.stdout.strip() else "INSPECTION_FAILED"


def inspect_package(path: Path) -> dict[str, Any]:
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
                    "official_evidence_url", "store_id", "name", "publisher", "version"}
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
        return raw


def compare_package_identity(package: dict[str, Any], official: dict[str, Any]) -> None:
    if package.get("kind") not in {"msix", "appx"}:
        raise HoldError("Official Identity cannot be approved from an EXE-only candidate")
    checks = (("package_identity", "name"), ("publisher", "publisher"), ("version", "version"))
    mismatches = [f"{left}!={right}" for left, right in checks if package.get(left) != official.get(right)]
    if mismatches:
        raise ConflictError("Package and official Identity mismatch: " + ", ".join(mismatches))


def windows_all_auto_record(job: Job, official: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "type": {"APP": "app", "GAME": "game", "GAME_3D": "3d-game"}[job.product_type],
            "slug": job.slug, "expected_head_sha": job.source_sha,
            "official_evidence_url": official["official_evidence_url"], "operator_verified": True,
            "verified_by": official["authenticated_account"],
            "identity": {key: official[key] for key in ("store_id", "name", "publisher", "version")}}


class GitHubReturnClient:
    MUTATION = "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input:$input) { commit { oid url } } }"

    def __init__(self, api: Callable[..., Any] | None = None):
        self.api = api or self._gh_api

    def return_identity(self, job: Job, config: ProductConfig, official: dict[str, Any], apply: bool) -> dict[str, Any]:
        target_path = f"products/{job.slug}/store/approved-identity.json"
        base = f"repos/{config.source_repository}/"
        proposal = {"status": "NOT_APPLIED", "repository": config.source_repository, "branch": config.source_branch,
                    "path": target_path, "commit_sha": None, "commit_url": None}
        if not apply:
            return proposal
        ref = self.api(base + "git/ref/heads/" + config.source_branch)
        if not isinstance(ref, dict) or ref.get("object", {}).get("sha") != job.source_sha:
            raise ConflictError("Factory HEAD changed before identity return")
        self._verify_product(base, job, config)
        existing = self.api(base + "contents/" + target_path + "?ref=" + quote(config.source_branch, safe=""), allow_missing=True)
        if existing is not None:
            if self._existing_matches(existing, official):
                return {**proposal, "status": "EXISTING_VERIFIED", "commit_sha": existing.get("sha")}
            raise ConflictError("approved-identity.json already exists and will not be overwritten")
        approved = {"reviewed": True, "source": "partner_center", "store_id": official["store_id"],
                    "name": official["name"], "publisher": official["publisher"], "version": official["version"],
                    "verified_by": official["authenticated_account"], "evidence_url": official["official_evidence_url"]}
        content = json.dumps(approved, ensure_ascii=False, indent=2) + "\n"
        body = {"query": self.MUTATION, "variables": {"input": {
            "branch": {"repositoryNameWithOwner": config.source_repository, "branchName": config.source_branch},
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
        branch = quote(config.source_branch, safe="")
        if config.product_type == "GAME_3D":
            item = self.api(base + f"contents/products/{job.slug}/project.godot?ref=" + branch)
            if b"run/main_scene" not in self._decode_content(item, 128_000):
                raise ConflictError("Pinned 3D product project.godot is invalid")
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
    def _existing_matches(existing: dict[str, Any], official: dict[str, Any]) -> bool:
        if existing.get("encoding") != "base64":
            return False
        try:
            content = json.loads(base64.b64decode(existing["content"], validate=True))
        except Exception:
            return False
        return all(content.get(key) == official.get(key) for key in ("store_id", "name", "publisher", "version"))

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
                 identity: OfficialIdentityProvider | None = None, github: GitHubReturnClient | None = None):
        self.config = config
        self.ledger = Ledger(state_dir / config.product_type.lower())
        self.work_dir = work_dir / config.product_type.lower()
        self.source, self.builder = source or SourceManager(), builder or PackageBuilder()
        self.identity, self.github = identity or OfficialIdentityProvider(None), github or GitHubReturnClient()

    def run(self, raw: dict[str, Any], apply: bool = False) -> dict[str, Any]:
        started = utc_now()
        try:
            job = Job.validate(raw, self.config)
        except ProvisionerError as exc:
            return self._error_response(raw, exc, started)
        try:
            with self.ledger.lock(job.request_id):
                previous = self.ledger.read(job.request_id)
                # A reviewed dry-run may become live without changing the request ID.
                # Compare every other field, including Factory SHA, product and actions.
                # Preserve the original ledger on conflicts: a mismatched retry must
                # never replace the binding of request_id to its original product.
                prior_status = (previous or {}).get("response", {}).get("status")
                promoted = bool(
                    previous and prior_status == "DRY_RUN" and not job.dry_run
                    and previous.get("fingerprint")
                    == canonical_hash({**asdict(job), "dry_run": True})
                )
                if previous and previous.get("fingerprint") != job.fingerprint() and not promoted:
                    response = self._base_response(job, "CONFLICT", started)
                    response["errors"] = ["request_id was previously used for different input"]
                    response["next_stage"] = "RECONCILE_CONFLICT"
                    return response
                if previous and prior_status in FINAL_STATUSES and not promoted:
                    return {**previous["response"], "idempotent_replay": True}
                if job.dry_run:
                    response = self._base_response(job, "DRY_RUN", started)
                    response["next_stage"] = "SUBMIT_NON_DRY_RUN_AFTER_REVIEW"
                    self._save(job, response, {"stage": "DRY_RUN_VALIDATED"})
                    return response
                try:
                    root = self.work_dir / hashlib.sha256(job.request_id.encode()).hexdigest()[:16]
                    source_dir = self.source.acquire(job, root / "source")
                    package = inspect_package(self.builder.build(job, source_dir, root / "artifacts", self.config))
                    official = self.identity.lookup(job)
                    compare_package_identity(package, official)
                    contract = windows_all_auto_record(job, official)
                    returned = self.github.return_identity(job, self.config, official, apply=apply)
                    status = "COMPLETED" if returned["status"] in {"APPLIED", "EXISTING_VERIFIED"} else "HOLD"
                    response = self._base_response(job, status, started)
                    response.update(package=package, official_identity={
                        "status": "VERIFIED_OPERATOR_EXPORT", **{k: official[k] for k in
                        ("store_id", "name", "publisher", "version", "official_evidence_url", "verified_at")}},
                        windows_all_auto_record=contract, github_return=returned,
                        next_stage="GITHUB_REBUILD_MSIX" if status == "COMPLETED" else "APPLY_VERIFIED_GITHUB_RETURN")
                    if status == "HOLD":
                        response["errors"] = ["Identity verified locally but GitHub return was not applied; rerun with --apply after review"]
                    self._save(job, response, {"stage": returned["status"], "package_sha256": package["sha256"]})
                    return response
                except ProvisionerError as exc:
                    return self._record_error(job, exc, started, previous)
                except Exception as exc:
                    return self._record_error(job, ProvisionerError(f"Unexpected local failure: {type(exc).__name__}"), started, previous)
        except ProvisionerError as exc:
            return self._error_response(raw, exc, started)

    def _base_response(self, job: Job, status: str, started: str) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "request_id": job.request_id, "product_type": job.product_type,
                "status": status, "source_repository": job.source_repository, "source_branch": job.source_branch,
                "source_sha": job.source_sha, "slug": job.slug, "started_at": started, "finished_at": utc_now(),
                "idempotent_replay": False,
                "package": {"status": "NOT_BUILT", "sha256": None, "path": None, "package_identity": None,
                            "publisher": None, "version": None, "package_family_name": None, "package_sid": None,
                            "signature_status": None},
                "official_identity": {"status": "UNVERIFIED", "store_id": None, "name": None, "publisher": None,
                                      "version": None, "official_evidence_url": None},
                "github_return": {"status": "NOT_APPLIED", "repository": self.config.source_repository,
                                  "branch": self.config.source_branch,
                                  "path": f"products/{job.slug}/store/approved-identity.json", "commit_sha": None},
                "windows_all_auto_record": None, "errors": [], "next_stage": None}

    def _error_response(self, raw: dict[str, Any], exc: ProvisionerError, started: str) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION,
                "request_id": raw.get("request_id") if isinstance(raw.get("request_id"), str) else None,
                "product_type": raw.get("product_type") if isinstance(raw.get("product_type"), str) else self.config.product_type,
                "status": exc.status, "source_repository": raw.get("source_repository"), "source_sha": raw.get("source_sha"),
                "package": {"status": "NOT_BUILT", "sha256": None},
                "official_identity": {"status": "UNVERIFIED", "store_id": None},
                "github_return": {"status": "NOT_APPLIED", "commit_sha": None},
                "errors": [redact(str(exc))], "next_stage": exc.next_stage,
                "started_at": started, "finished_at": utc_now(), "idempotent_replay": False}

    def _record_error(self, job: Job, exc: ProvisionerError, started: str,
                      previous: dict[str, Any] | None) -> dict[str, Any]:
        response = self._base_response(job, exc.status, started)
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
    parser.add_argument("--apply", action="store_true", help="Atomically write to the configured Factory work branch")
    args = parser.parse_args(argv)
    started = utc_now()
    try:
        config, raw = ProductConfig.load(args.config), load_json(args.input)
        result = Provisioner(config, args.state_dir, args.work_dir,
                             identity=OfficialIdentityProvider(args.official_identity)).run(raw, apply=args.apply)
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
