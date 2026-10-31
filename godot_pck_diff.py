"""Diagnostic-only Godot 4.3 PCK v2 member comparison.

Does not approve Store packaging, Identity, or reproducible export. Godot 4.3
PCK layout follows core/io/file_access_pack.cpp (4.3-stable).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import struct

MAX_PACK_BYTES = 2_000_000_000
MAX_MEMBERS = 100_000
MAX_PATH_BYTES = 16_384
MAX_SMALL_MEMBER_DIAGNOSTIC_BYTES = 4096


def _read_exact(stream, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated PCK directory or header")
    return data


def _digest_stream(stream, size: int) -> tuple[str, bytes]:
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    remaining = size
    while remaining:
        chunk = _read_exact(stream, min(remaining, 1024 * 1024))
        sha.update(chunk)
        md5.update(chunk)
        remaining -= len(chunk)
    return sha.hexdigest(), md5.digest()


def inventory_pck(path: Path, *, capture_small_members: bool = False) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("PCK is not a regular file")
    total = path.stat().st_size
    if total < 100 or total > MAX_PACK_BYTES:
        raise ValueError("PCK size is outside diagnostic limits")
    with path.open("rb") as stream:
        header = _read_exact(stream, 96)
        magic, fmt, major, minor, patch, flags = struct.unpack_from("<4sIIIII", header)
        base = struct.unpack_from("<Q", header, 24)[0]
        if magic != b"GDPC" or fmt != 2 or (major, minor) != (4, 3):
            raise ValueError("unsupported Godot PCK format/version (requires Godot 4.3 v2)")
        if flags & ~2:
            raise ValueError("encrypted/sparse/unknown PCK flags are not supported")
        count = struct.unpack("<I", _read_exact(stream, 4))[0]
        if not 0 < count <= MAX_MEMBERS:
            raise ValueError("PCK member count outside diagnostic limits")
        entries = []
        names = set()
        for _ in range(count):
            length = struct.unpack("<I", _read_exact(stream, 4))[0]
            if not 0 < length <= MAX_PATH_BYTES:
                raise ValueError("invalid PCK member path length")
            raw = _read_exact(stream, length)
            name = raw.rstrip(b"\0").decode("utf-8")
            if name.startswith("res://"):
                name = name[6:]
            if (not name or name.startswith("/") or "\\" in name
                    or any(part in ("", ".", "..") for part in name.split("/"))
                    or name in names):
                raise ValueError("duplicate or unsafe PCK member path")
            names.add(name)
            offset, size = struct.unpack("<QQ", _read_exact(stream, 16))
            expected_md5 = _read_exact(stream, 16)
            member_flags = struct.unpack("<I", _read_exact(stream, 4))[0]
            if member_flags:
                raise ValueError("encrypted/removed/unknown PCK member flags")
            # Godot adds file_base for v2 even when PACK_REL_FILEBASE is unset.
            # The flag controls adjustment for an embedded pack's start offset.
            absolute = offset + base
            if absolute > total or size > total - absolute:
                raise ValueError("PCK member payload outside file")
            entries.append((name, absolute, size, expected_md5))
        members = {}
        small_members = {}
        for name, absolute, size, expected_md5 in entries:
            stream.seek(absolute)
            sha, actual_md5 = _digest_stream(stream, size)
            if actual_md5 != expected_md5:
                raise ValueError("PCK member checksum mismatch")
            members[name] = {"sha256": sha, "size_bytes": size}
            if capture_small_members and size <= MAX_SMALL_MEMBER_DIAGNOSTIC_BYTES:
                stream.seek(absolute)
                small_members[name] = _read_exact(stream, size)
        stream.seek(0)
        full_sha, _ = _digest_stream(stream, total)
    result = {"sha256": full_sha, "size_bytes": total,
              "godot_version": f"{major}.{minor}.{patch}", "pck_format": fmt,
              "member_count": count, "members": members}
    if capture_small_members:
        result["_small_members"] = small_members
    return result


def _small_byte_diff(factory: bytes, local: bytes) -> dict:
    """Bounded binary evidence only; never infer semantic equivalence."""
    common = min(len(factory), len(local))
    differing = [i for i in range(common) if factory[i] != local[i]]
    first = differing[0] if differing else common
    count = len(differing) + abs(len(factory) - len(local))
    start = max(0, first - 12)
    end = first + 16
    return {"first_differing_offset": first, "differing_byte_count": count,
            "factory_hex_window": factory[start:end].hex(),
            "local_hex_window": local[start:end].hex(),
            "hex_window_start": start,
            "interpretation": "BINARY_DIAGNOSTIC_ONLY_NOT_SEMANTIC_PROOF"}


# A five-character PackedScene identifier is a *candidate* for a transient
# Godot resource name, not proof that two compiled scenes behave identically.
# Require an identical binary payload after replacing exactly one identifier.
_PACKED_SCENE_ID = re.compile(rb"PackedScene_([a-z0-9]{5})(?=\x00)")


def _only_packed_scene_identifier_diff(factory: bytes, local: bytes) -> bool:
    if factory == local or len(factory) != len(local):
        return False
    left = list(_PACKED_SCENE_ID.finditer(factory))
    right = list(_PACKED_SCENE_ID.finditer(local))
    if len(left) != 1 or len(right) != 1:
        return False
    a, b = left[0], right[0]
    if a.start(1) != b.start(1):
        return False
    start, end = a.span(1)
    return (factory[:start] == local[:start]
            and factory[end:] == local[end:]
            and factory[start:end] != local[start:end])


def compare_pcks(factory: Path, local: Path) -> dict:
    a = inventory_pck(factory, capture_small_members=True)
    b = inventory_pck(local, capture_small_members=True)
    a_small, b_small = a.pop("_small_members"), b.pop("_small_members")
    left, right = a.pop("members"), b.pop("members")
    only_factory = sorted(left.keys() - right.keys())
    only_local = sorted(right.keys() - left.keys())
    changed = sorted(k for k in left.keys() & right.keys() if left[k] != right[k])
    if a["sha256"] == b["sha256"]:
        status = "BYTE_IDENTICAL"
    elif not (only_factory or only_local or changed):
        status = "MEMBERS_IDENTICAL_CONTAINER_DIFF"
    else:
        status = "MEMBER_CONTENT_DIFF"
    changed_details = []
    for name in changed[:30]:
        item = {"path": name, "factory": left[name], "local": right[name]}
        if name in a_small and name in b_small:
            item["small_member_byte_diff"] = _small_byte_diff(a_small[name], b_small[name])
            item["packed_scene_id_only_candidate"] = (
                name.endswith(".scn")
                and _only_packed_scene_identifier_diff(a_small[name], b_small[name]))
        changed_details.append(item)
    scene_id_only_candidate = (
        not only_factory and not only_local and len(changed) == 1
        and changed_details[0].get("packed_scene_id_only_candidate") is True)
    return {"diagnostic_status": status, "factory": a, "local_reexport": b,
            "scene_id_only_drift_candidate": scene_id_only_candidate,
            "scene_id_drift_interpretation": "BINARY_PATTERN_ONLY_NOT_SEMANTIC_PROOF",
            "only_in_factory_count": len(only_factory),
            "only_in_local_count": len(only_local),
            "changed_count": len(changed),
            "only_in_factory": only_factory[:30],
            "only_in_local": only_local[:30],
            "changed": changed_details,
            "report_truncated": any(len(x) > 30 for x in (only_factory, only_local, changed)),
            "reproducible_export_approved": False,
            "official_identity_cas_verified": False,
            "store_submission_allowed": False,
            "product_e2e": "HOLD"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--factory", required=True, type=Path)
    parser.add_argument("--local", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = compare_pcks(args.factory, args.local)
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        result = {"diagnostic_status": "INSPECTION_UNAVAILABLE",
                  "error_type": type(exc).__name__, "error": str(exc)[:200],
                  "reproducible_export_approved": False,
                  "official_identity_cas_verified": False,
                  "store_submission_allowed": False, "product_e2e": "HOLD"}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("changed", "only_in_factory", "only_in_local")}, sort_keys=True))


if __name__ == "__main__":
    main()
