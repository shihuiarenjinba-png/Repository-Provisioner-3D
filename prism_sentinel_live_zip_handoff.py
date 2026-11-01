"""Fail-closed, byte-level Prism Sentinel Factory ZIP -> 36-lane check-only handoff.

Run with a freshly downloaded GitHub Actions artifact ZIP. This verifies actual
bytes, unlike metadata-only checks. Neither ZIP nor UI fixture grants Store CAS.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import stat
import zipfile


PINNED = {
    "source_sha": "e432d94ed0db22878f61f1a8af140d7d7de2288f",
    "request_id": "3d-prism-route-3d-e432d94ed0db",
    "source_branch": "codex/prism-route-trap-tension-20261029",
    "source_repository": "shihuiarenjinba-png/3d-game-factory",
    "slug": "prism-route-3d",
    "factory_run_id": 40901053437,
    "artifact_id": 12909162367,
    "archive_size": 30880705,
    "archive_sha256": "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c",
    "expires_at": "2026-11-05T15:24:12Z",
    "members": {
        "candidate.exe": (84214784, "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"),
        "candidate.pck": (71568, "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"),
        "export-evidence.json": (672, "c55db8c276919cc9792c02f2423ecc6e7b249ad83772e9e256de1fd412208103"),
    },
}
LEGACY_PCK = "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"


class GateError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise GateError(reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_zip(path, *, expected=PINNED, live_metadata=None, now=None):
    """Verify actual archive and return a non-authorizing receipt.

    expected injection is solely for synthetic unit tests. The CLI always uses
    the pinned production constants above, not caller-provided expectations.
    """
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "missing or symlink ZIP")
    require(0 < path.stat().st_size <= 120_000_000, "unsafe archive size")
    raw = path.read_bytes()
    require(len(raw) == expected["archive_size"], "Factory archive size drift")
    require(sha256(raw) == expected["archive_sha256"], "Factory archive SHA256 drift")
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            require(len(names) == len(set(names)), "duplicate ZIP member")
            require(set(names) == set(expected["members"]) and len(names) == 3,
                    "ZIP members differ from pinned EXE/PCK/manifest")
            require(all(not stat.S_ISLNK(i.external_attr >> 16) for i in infos),
                    "symlink member")
            require(sum(i.file_size for i in infos) <= 100_000_000,
                    "unsafe uncompressed total")
            require(z.testzip() is None, "ZIP CRC failure")
            for info in infos:
                size, digest = expected["members"][info.filename]
                require(info.file_size == size, "member size drift: " + info.filename)
                require(sha256(z.read(info)) == digest, "member SHA drift: " + info.filename)
            manifest = json.loads(z.read("export-evidence.json"),
                                  object_pairs_hook=unique_object)
    except (zipfile.BadZipFile, EOFError, OSError) as exc:
        raise GateError("unreadable Factory ZIP") from exc
    fields = {
        "source_sha": expected["source_sha"],
        "request_id": expected["request_id"],
        "factory_build_head": expected["source_sha"],
        "source_branch": expected["source_branch"],
        "source_repository": expected["source_repository"],
        "slug": expected["slug"],
        "product_type": "GAME_3D",
        "exe_path": "candidate.exe",
        "pck_path": "candidate.pck",
        "exe_sha256": expected["members"]["candidate.exe"][1],
        "pck_sha256": expected["members"]["candidate.pck"][1],
        "exe_size_bytes": expected["members"]["candidate.exe"][0],
        "pck_size_bytes": expected["members"]["candidate.pck"][0],
        "schema_version": 1,
    }
    require(type(manifest) is dict and manifest == fields, "manifest/source/request/build drift")
    require(manifest["pck_sha256"] != LEGACY_PCK, "legacy PCK not Sentinel")
    current = datetime.now(timezone.utc) if now is None else now
    require(isinstance(current, datetime) and current.tzinfo is not None and
            current.utcoffset() is not None, "timezone-aware now required")
    expiry = datetime.fromisoformat(expected["expires_at"].replace("Z", "+00:00"))
    require(current.astimezone(timezone.utc) < expiry, "Factory Artifact expired by UTC deadline")
    live_checked = False
    if live_metadata is not None:
        m = live_metadata
        require(type(m) is dict and m.get("id") == expected["artifact_id"] and
                type(m.get("size_in_bytes")) is int and
                m["size_in_bytes"] == expected["archive_size"] and
                m.get("digest") == "sha256:" + expected["archive_sha256"] and
                m.get("expires_at") == expected["expires_at"] and
                m.get("expired") is False and
                type(m.get("workflow_run")) is dict and
                m["workflow_run"].get("head_sha") == expected["source_sha"],
                "live GitHub metadata mismatch")
        live_checked = True
    return {
        "handoff_type": "PRISM_SENTINEL_LIVE_ZIP_CHECK_ONLY",
        "slug": expected["slug"],
        "source_sha": expected["source_sha"],
        "request_id": expected["request_id"],
        "factory_build_head": expected["source_sha"],
        "factory_run_id": expected["factory_run_id"],
        "factory_artifact_id": expected["artifact_id"],
        "archive_sha256": expected["archive_sha256"],
        "exe_sha256": manifest["exe_sha256"],
        "pck_sha256": manifest["pck_sha256"],
        "archive_bytes_verified_this_run": True,
        "manifest_correlated": True,
        "live_artifact_metadata_checked": live_checked,
        "registration_type": "MSIX_OR_PWA_GAME",
        "partner_center_selection": "MSIX or PWA game",
        "historical_store_id_reference_only": "9N95J2T57B41",
        "historical_identity_commit_reference_only": "11417b75636ee18816028ffd5221884c4c9a9836",
        "historical_identity_rebound_to_sentinel": False,
        "identity_return_target": "products/prism-route-3d/store/approved-identity.json",
        "required_ui_recheck": ["Store ID", "reserved display name", "Package Identity Name",
                                "Publisher", "Publisher Display Name", "PFN", "Package SID"],
        "official_identity_cas": "HOLD",
        "approved_package_version": "HOLD",
        "signed_product_msix": "HOLD",
        "unsigned_qa_fixture_is_product": False,
        "windows_all_auto_intake": "HOLD",
        "local_windows_gate": "DEFERRED_LOCAL_GATE",
        "product_e2e": "HOLD",
        "store_submission_allowed": False,
        "next_owner": "36-minute Windows/E2E official UI/CAS lane",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--factory-zip", type=Path, required=True)
    parser.add_argument("--live-metadata-json", type=Path)
    args = parser.parse_args(argv)
    try:
        metadata = (json.loads(args.live_metadata_json.read_text(encoding="utf-8"),
                               object_pairs_hook=unique_object)
                    if args.live_metadata_json else None)
        result = check_zip(args.factory_zip, live_metadata=metadata)
    except (GateError, ValueError, OSError, TypeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)[:180],
                          "product_e2e": "HOLD", "store_submission_allowed": False}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0  # Byte check succeeded; Store/CAS still HOLD.


if __name__ == "__main__":
    raise SystemExit(main())
