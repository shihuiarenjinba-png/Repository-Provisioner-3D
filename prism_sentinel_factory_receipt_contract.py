"""Fail-closed cross-contract check for the *historical* real Sentinel Factory receipt.

This validates receipt <-> Provisioner handoff consistency against independent,
pinned anchors. It does NOT download bytes, authenticate a Partner Center capture,
authorize CAS, or promote the unsigned QA fixture into a Store MSIX.
"""
from __future__ import annotations

SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
LEGACY_SOURCE = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
LEGACY_PCK = "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"
EXE = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK = "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"
ARCHIVE = "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c"
MANIFEST_SHA = "c55db8c276919cc9792c02f2423ecc6e7b249ad83772e9e256de1fd412208103"
RETURN_TARGET = "products/prism-route-3d/store/approved-identity.json"
MEMBERS = {
    "candidate.exe": (84214784, EXE),
    "candidate.pck": (71568, PCK),
    "export-evidence.json": (672, MANIFEST_SHA),
}


class ContractError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ContractError(reason)


def check(receipt, handoff):
    """Structural correlation only; always HOLD even for an exact positive receipt."""
    require(type(receipt) is dict and type(handoff) is dict, "missing evidence")
    require(receipt.get("receipt_type") == "GAME_3D_LIVE_FACTORY_ARCHIVE_RECHECK"
            and receipt.get("slug") == handoff.get("slug") == "prism-route-3d"
            and handoff.get("product") == receipt.get("product") == "Prism Route 3D",
            "wrong product or receipt role")
    source, artifact, manifest, members, checks = (
        receipt.get(k) for k in
        ("source", "artifact", "manifest", "members", "independent_checks"))
    require(all(type(v) is dict for v in
                (source, artifact, manifest, members, checks)), "incomplete receipt")
    require(source.get("sha") == source.get("factory_build_head")
            == handoff.get("source_sha") == handoff.get("factory_build_head")
            == manifest.get("source_sha") == manifest.get("factory_build_head") == SOURCE,
            "source/build head mismatch")
    require(source.get("request_id") == handoff.get("request_id")
            == manifest.get("request_id") == REQUEST, "request mismatch")
    require(source.get("repository") == handoff.get("source_repository")
            == manifest.get("source_repository")
            == "shihuiarenjinba-png/3d-game-factory"
            and source.get("branch") == handoff.get("source_branch")
            == manifest.get("source_branch") == "codex/prism-route-trap-tension-20261029",
            "source repository/branch mismatch")
    factory = handoff.get("factory")
    require(type(factory) is dict, "missing Factory handoff")
    require(type(artifact.get("workflow_run_id")) is int
            and artifact["workflow_run_id"] == factory.get("run_id") == 40901053437
            and type(artifact.get("artifact_id")) is int
            and artifact["artifact_id"] == factory.get("artifact_id") == 12909162367
            and artifact.get("archive_sha256") == ARCHIVE
            and artifact.get("github_metadata_digest") == "sha256:" + ARCHIVE
            and artifact.get("archive_size_bytes") == 30880705
            and artifact.get("github_workflow_head_sha") == SOURCE
            and artifact.get("github_metadata_expired") is False
            and artifact.get("expires_at") == factory.get("artifact_expires_at")
            == "2026-11-05T15:24:12Z", "Factory archive identity drift")
    require(set(members) == set(MEMBERS), "unexpected archive member")
    for name, (size, sha) in MEMBERS.items():
        member = members[name]
        require(type(member) is dict and type(member.get("size_bytes")) is int
                and member["size_bytes"] == size and member.get("sha256") == sha,
                "archive member drift: " + name)
    require(manifest.get("schema_version") == 1
            and manifest.get("product_type") == "GAME_3D"
            and manifest.get("slug") == "prism-route-3d"
            and manifest.get("exe_path") == "candidate.exe"
            and manifest.get("pck_path") == "candidate.pck"
            and manifest.get("exe_sha256") == factory.get("exe_sha256") == EXE
            and manifest.get("pck_sha256") == factory.get("pck_sha256") == PCK
            and manifest.get("exe_size_bytes") == MEMBERS["candidate.exe"][0]
            and manifest.get("pck_size_bytes") == MEMBERS["candidate.pck"][0],
            "manifest/payload mismatch")
    zip_meta = receipt.get("zip")
    require(type(zip_meta) is dict
            and zip_meta.get("exact_members") is not None
            and len(zip_meta["exact_members"]) == 3
            and set(zip_meta["exact_members"]) == set(MEMBERS)
            and zip_meta.get("crc_test_passed") is True
            and zip_meta.get("symlink_members_present") is False
            and zip_meta.get("uncompressed_total_bytes") == 84287024,
            "archive safety claim mismatch")
    require(all(checks.get(k) is True for k in (
        "archive_matches_github_digest", "workflow_head_matches_source",
        "source_request_build_head_match_manifest", "exe_sha_and_size_match_manifest",
        "pck_sha_and_size_match_manifest", "archive_members_exact", "crc_pass")),
        "independent checks incomplete")
    legacy = receipt.get("legacy_provisioner_discrimination")
    newer = handoff.get("newer_20261101_workflow")
    require(type(legacy) is dict and type(newer) is dict
            and legacy.get("legacy_source_sha") == newer.get("source_sha") == LEGACY_SOURCE
            and legacy.get("legacy_pck_sha256") == newer.get("pck_sha256") == LEGACY_PCK
            and LEGACY_PCK != PCK
            and legacy.get("legacy_pck_matches_sentinel") is False
            and legacy.get("legacy_promotable_to_sentinel") is False
            and newer.get("same_pck_as_sentinel") is False
            and newer.get("promotable_to_sentinel") is False,
            "legacy revision incorrectly promoted")
    require(receipt.get("registration_type") == handoff.get("registration_type")
            == "MSIX_OR_PWA_GAME"
            and receipt.get("partner_center_selection")
            == handoff.get("partner_center_selection") == "MSIX or PWA game",
            "registration route mismatch")
    old = handoff.get("historical_identity")
    downstream = receipt.get("downstream")
    fixture = handoff.get("unsigned_qa_fixture")
    require(type(old) is dict and type(downstream) is dict and type(fixture) is dict,
            "missing downstream/Identity evidence")
    require(old.get("reference_commit") == downstream.get("historical_identity_commit")
            == "11417b75636ee18816028ffd5221884c4c9a9836"
            and old.get("source_sha") == LEGACY_SOURCE
            and old.get("verified_for_sentinel") is False
            and downstream.get("historical_identity_rebound_to_sentinel") is False
            and downstream.get("identity_return_target")
            == handoff.get("identity_return_target") == RETURN_TARGET,
            "historical Identity incorrectly rebound")
    require(fixture.get("fixture_identity") == "Example.ThreeD.Fixture"
            and fixture.get("signature_present") is False
            and fixture.get("store_product_msix") is False
            and downstream.get("unsigned_qa_fixture_is_store_package") is False,
            "unsigned QA fixture promoted")
    require(all(downstream.get(k) == handoff.get(k) == "HOLD" for k in (
        "official_identity_cas", "package_version", "signed_product_msix",
        "windows_all_auto_intake", "product_e2e"))
            and downstream.get("store_submission_allowed") is False
            and handoff.get("store_submission_allowed") is False
            and downstream.get("second_3d_product_allowed") is False
            and handoff.get("second_3d_product_allowed") is False,
            "unapproved downstream promotion")
    return {
        "status": "HOLD_HISTORICAL_FACTORY_RECEIPT_CORRELATED",
        "factory_receipt_structurally_correlated": True,
        "live_archive_bytes_verified_by_this_check": False,
        "official_identity_cas_verified": False,
        "signed_product_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD",
        "store_submission_allowed": False,
    }
