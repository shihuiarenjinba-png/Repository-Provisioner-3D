"""Fail-closed Provisioner contract for the current Prism Route 3D source.

This module validates a pinned, append-only handoff. It does not contact
Partner Center, mutate the 36-owner ledger, build/sign an MSIX, or authorize
Store submission.
"""
from __future__ import annotations

SOURCE_REPO = "shihuiarenjinba-png/3d-game-factory"
SOURCE_BRANCH = "codex/prism-tower1-hud-clearance-fix-20261103"
SOURCE_SHA = "b03ce7b16c3f75c04fe20fdda224c45849eeba0d"
REQUEST_ID = "3d-prism-route-3d-b03ce7b16c3f"
FACTORY_RUN_ID = 43794658086
FACTORY_ARTIFACT_ID = 14797309778
FACTORY_ZIP_SHA256 = "e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac"
EXE_SHA256 = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK_SHA256 = "b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666"
EXPORT_MANIFEST_SHA256 = "442d2c9070e017adf1c0ceaa96ba607f470c0f147176671f8a844122aca4d5bd"
REGISTRATION_TYPE = "MSIX_OR_PWA_GAME"
PARTNER_CENTER_SELECTION = "MSIX or PWA game"
HISTORICAL_IDENTITY_SOURCE_SHA = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
QA_REPO = "shihuiarenjinba-png/3d-build-qa"
QA_PR19_HEAD = "9b90bfc9dfa6ded9699c3f22df45390be909dae8"
QA_PR20_HEAD = "31032210446e5de7376a82698d854d25a51da2f9"
QA_CUSTODY_ARTIFACT_ID = 15233410594
QA_CUSTODY_ARTIFACT_SHA256 = "a02ed2a03ef37ebdb4dc46ad31c84148da3949fb1e55c5b0e0ae3627769f1b9f"
MAKEAPPX_ARTIFACT_ID = 15233068292
MAKEAPPX_ARTIFACT_SHA256 = "aaf107e7dee1d07da923d57dfeae435ce198ef5581e158e1c86765df261a7f87"

EXPECTED_MAPPING = (
    (
        "candidate.exe",
        "VFS/ProgramFilesX64/PrismRoute3D/candidate.exe",
        84214784,
        EXE_SHA256,
    ),
    (
        "candidate.pck",
        "VFS/ProgramFilesX64/PrismRoute3D/candidate.pck",
        6987584,
        PCK_SHA256,
    ),
)
EXPECTED_ASSETS = (
    ("properties_logo", "Assets/StoreLogo.png"),
    ("square_150x150_logo", "Assets/Square150x150Logo.png"),
    ("square_44x44_logo", "Assets/Square44x44Logo.png"),
)


class HandoffError(ValueError):
    """The supplied handoff is stale, inconsistent, or attempts promotion."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise HandoffError(reason)


def validate(handoff: dict) -> dict:
    """Validate the exact current-source package-readiness snapshot.

    A successful result means only that the handoff is internally consistent.
    The returned status is deliberately not a package, Identity, QA, or sale
    approval.
    """
    _require(type(handoff) is dict, "handoff must be an object")
    _require(handoff.get("schema_version") == 1, "unsupported schema")
    _require(
        handoff.get("receipt_type") == "GAME_3D_CURRENT_SOURCE_PACKAGE_READINESS",
        "wrong receipt type",
    )
    _require(handoff.get("product") == "Prism Route 3D", "wrong product")
    _require(handoff.get("slug") == "prism-route-3d", "wrong product slug")

    source = handoff.get("source")
    _require(type(source) is dict, "missing current source")
    _require(source.get("repository") == SOURCE_REPO, "source repository mismatch")
    _require(source.get("branch") == SOURCE_BRANCH, "source branch mismatch")
    _require(
        source.get("sha") == SOURCE_SHA
        and source.get("factory_build_head") == SOURCE_SHA,
        "source SHA / Factory build HEAD mismatch",
    )
    _require(source.get("request_id") == REQUEST_ID, "source/request mismatch")
    _require(source.get("product_type") == "GAME_3D", "product type mismatch")

    factory = handoff.get("factory_export")
    _require(type(factory) is dict, "missing Factory export")
    _require(factory.get("workflow_run_id") == FACTORY_RUN_ID, "Factory run mismatch")
    _require(factory.get("artifact_id") == FACTORY_ARTIFACT_ID, "Factory artifact mismatch")
    _require(
        factory.get("archive_sha256") == FACTORY_ZIP_SHA256,
        "Factory ZIP digest mismatch",
    )
    _require(factory.get("archive_size_bytes") == 37795977, "Factory ZIP size mismatch")
    _require(
        factory.get("original_expires_at_utc") == "2026-11-30T07:32:37Z",
        "original Factory retention metadata mismatch",
    )
    members = factory.get("members")
    _require(type(members) is dict, "Factory member inventory missing")
    for name, size, digest in (
        ("candidate.exe", 84214784, EXE_SHA256),
        ("candidate.pck", 6987584, PCK_SHA256),
        ("export-evidence.json", 680, EXPORT_MANIFEST_SHA256),
    ):
        member = members.get(name)
        _require(type(member) is dict, "Factory member missing: " + name)
        _require(member.get("size_bytes") == size, "Factory member size mismatch: " + name)
        _require(member.get("sha256") == digest, "Factory member SHA mismatch: " + name)

    manifest = factory.get("export_manifest")
    _require(type(manifest) is dict, "export manifest evidence missing")
    _require(manifest.get("source_repository") == SOURCE_REPO, "manifest repository mismatch")
    _require(manifest.get("source_branch") == SOURCE_BRANCH, "manifest branch mismatch")
    _require(
        manifest.get("source_sha") == SOURCE_SHA
        and manifest.get("factory_build_head") == SOURCE_SHA,
        "manifest source/build HEAD mismatch",
    )
    _require(manifest.get("request_id") == REQUEST_ID, "manifest request mismatch")
    _require(
        manifest.get("exe_path") == "candidate.exe"
        and manifest.get("pck_path") == "candidate.pck",
        "manifest EXE/PCK paths mismatch",
    )
    _require(factory.get("exact_bytes_reverified_by_qa") is True, "exact byte recheck missing")

    durable = factory.get("durable_exact_bytes_copy")
    _require(type(durable) is dict, "durable exact-byte copy missing")
    _require(durable.get("repository") == QA_REPO, "custody repository mismatch")
    _require(durable.get("pull_request") == 20, "custody PR mismatch")
    _require(durable.get("run_id") == 46071743617, "custody run mismatch")
    _require(durable.get("artifact_id") == QA_CUSTODY_ARTIFACT_ID, "custody artifact mismatch")
    _require(
        durable.get("sha256") == QA_CUSTODY_ARTIFACT_SHA256,
        "custody artifact digest mismatch",
    )
    _require(durable.get("size_bytes") == 167283608, "custody artifact size mismatch")
    _require(
        durable.get("status") == "EXACT_FACTORY_AND_HANDOFF_BYTES_PRESERVED_QA_ONLY",
        "custody status mismatch",
    )

    qa = handoff.get("independent_qa")
    _require(type(qa) is dict, "independent QA evidence missing")
    _require(qa.get("repository") == QA_REPO and qa.get("pr_number") == 19, "QA PR mismatch")
    _require(qa.get("exact_head") == QA_PR19_HEAD, "QA exact HEAD mismatch")
    cloud = qa.get("cloud_workflows")
    _require(
        type(cloud) is dict
        and cloud.get("total") == 8
        and cloud.get("success") == 8
        and cloud.get("status") == "SUCCESS_CLOUD_QA_ONLY",
        "PR19 cloud QA status mismatch",
    )
    physical = qa.get("physical_windows_qa")
    _require(type(physical) is dict, "physical QA state missing")
    _require(
        physical.get("sessions_completed") == 0
        and physical.get("sessions_required") == 6
        and physical.get("screenshots_captured") == 0
        and physical.get("screenshots_required") == 36
        and physical.get("status") == "HOLD_NOT_PHYSICAL_QA",
        "physical QA must remain explicitly HOLD at 0/6 and 0/36",
    )
    physical_artifact = qa.get("physical_handoff_artifact")
    _require(type(physical_artifact) is dict, "physical handoff artifact missing")
    _require(physical_artifact.get("artifact_id") == 14952074847, "physical handoff artifact mismatch")
    _require(
        physical_artifact.get("sha256")
        == "35ae3ea873e0b122fe2cb138a170cd233cf89c7c81e8fed4262139d366a4c4c6",
        "physical handoff digest mismatch",
    )
    _require(physical_artifact.get("size_bytes") == 129481721, "physical handoff size mismatch")

    preflight = handoff.get("package_preflight")
    _require(type(preflight) is dict, "package preflight evidence missing")
    _require(preflight.get("repository") == QA_REPO, "preflight repository mismatch")
    _require(preflight.get("pr_number") == 20, "preflight PR mismatch")
    _require(preflight.get("exact_head") == QA_PR20_HEAD, "preflight exact HEAD mismatch")
    _require(preflight.get("base_pr19_head") == QA_PR19_HEAD, "preflight base mismatch")
    _require(preflight.get("run_id") == 46071743617, "preflight run mismatch")
    workflows = preflight.get("workflows")
    _require(
        type(workflows) is dict
        and workflows.get("total") == 9
        and workflows.get("success") == 9
        and workflows.get("status") == "SUCCESS_QA_ONLY",
        "preflight workflow status mismatch",
    )
    makeappx_artifact = preflight.get("makeappx_capability_artifact")
    _require(type(makeappx_artifact) is dict, "MakeAppx receipt artifact missing")
    _require(makeappx_artifact.get("artifact_id") == MAKEAPPX_ARTIFACT_ID, "MakeAppx artifact mismatch")
    _require(
        makeappx_artifact.get("sha256") == MAKEAPPX_ARTIFACT_SHA256,
        "MakeAppx artifact digest mismatch",
    )
    _require(makeappx_artifact.get("size_bytes") == 732, "MakeAppx artifact size mismatch")

    registration = handoff.get("registration")
    _require(type(registration) is dict, "registration route missing")
    _require(
        registration.get("type") == REGISTRATION_TYPE
        and registration.get("partner_center_selection") == PARTNER_CENTER_SELECTION
        and registration.get("gdk_route_allowed") is False,
        "registration route mismatch; GDK is not permitted",
    )

    layout = handoff.get("package_layout")
    _require(type(layout) is dict, "package layout missing")
    _require(layout.get("manifest_path") == "AppxManifest.xml", "manifest path mismatch")
    expected_exe = "VFS/ProgramFilesX64/PrismRoute3D/candidate.exe"
    expected_pck = "VFS/ProgramFilesX64/PrismRoute3D/candidate.pck"
    _require(layout.get("application_executable") == expected_exe, "Appx executable mapping mismatch")
    _require(layout.get("external_pck_sidecar") == expected_pck, "PCK sidecar mapping mismatch")
    mapping = layout.get("payload_mapping")
    _require(type(mapping) is list and len(mapping) == 2, "payload mapping must have two members")
    for actual, expected in zip(mapping, EXPECTED_MAPPING):
        _require(type(actual) is dict, "invalid payload mapping")
        source_member, package_path, size, digest = expected
        _require(actual.get("source_member") == source_member, "payload member mismatch")
        _require(actual.get("package_path") == package_path, "payload package path mismatch")
        _require(actual.get("size_bytes") == size, "payload size mismatch")
        _require(actual.get("sha256") == digest, "payload digest mismatch")

    assets = layout.get("required_store_assets")
    _require(type(assets) is list and len(assets) == len(EXPECTED_ASSETS), "required Store assets missing")
    for actual, expected in zip(assets, EXPECTED_ASSETS):
        _require(type(actual) is dict, "invalid Store asset mapping")
        role, path = expected
        _require(actual.get("role") == role and actual.get("package_path") == path, "Store asset role/path mismatch")
        _require(actual.get("source_path") is None, "unverified Store asset source must remain null")
        _require(
            actual.get("status") == "HOLD_OFFICIAL_ASSET_SOURCE_NOT_PRESENT",
            "missing Store asset cannot be promoted",
        )
    _require(
        layout.get("official_store_assets_status") == "HOLD_OFFICIAL_ASSET_SOURCE_NOT_PRESENT",
        "official Store asset gate mismatch",
    )
    source_manifest = layout.get("source_manifest")
    _require(type(source_manifest) is dict, "Factory product manifest summary missing")
    _require(source_manifest.get("store_identity") is None, "product manifest unexpectedly contains Identity")
    _require(
        source_manifest.get("registration_type") == REGISTRATION_TYPE
        and source_manifest.get("packaging_strategy") == "GODOT_WINDOWS_EXE_PCK_MAKEAPPX_MSIX"
        and source_manifest.get("package_version_gate") == "HOLD",
        "Factory product manifest gate mismatch",
    )

    capability = handoff.get("makeappx_capability")
    _require(type(capability) is dict, "MakeAppx capability report missing")
    _require(capability.get("scope") == "READ_ONLY_QA_CAPABILITY_ONLY", "MakeAppx scope mismatch")
    _require(capability.get("runner_image") == "win25-vs2026", "Windows runner image mismatch")
    _require(
        capability.get("executable_path")
        == r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\MakeAppx.exe",
        "MakeAppx path mismatch",
    )
    _require(
        capability.get("file_version") == "10.0.26100.9457 (WinBuild.160101.0800)",
        "MakeAppx file version mismatch",
    )
    _require(
        capability.get("sha256")
        == "58d5e69fd0322f960afbe34afed0eda66a5d001811ee838d1c7165130c3d55e5",
        "MakeAppx SHA mismatch",
    )
    _require(
        capability.get("authenticode_status") == "Valid"
        and "Microsoft Corporation" in capability.get("signer_subject", ""),
        "MakeAppx Microsoft signature mismatch",
    )
    _require(
        capability.get("status") == "MAKEAPPX_CAPABILITY_VERIFIED_READ_ONLY"
        and capability.get("help_probe_invoked") is True
        and capability.get("help_probe_contains_pack_usage") is True,
        "MakeAppx read-only capability was not verified",
    )
    _require(
        capability.get("makeappx_pack_invoked") is False
        and capability.get("package_file_created") is False
        and capability.get("product_msix_created") is False,
        "MakeAppx package creation must remain false",
    )

    identity = handoff.get("identity_gate")
    _require(type(identity) is dict, "Identity gate missing")
    _require(
        identity.get("status") == "HOLD_CURRENT_SOURCE_IDENTITY_REBIND_REQUIRED"
        and identity.get("historical_identity_source_sha") == HISTORICAL_IDENTITY_SOURCE_SHA
        and identity.get("historical_identity_is_current_source") is False
        and identity.get("current_source_sha") == SOURCE_SHA,
        "historical Identity must not be rebound to current source",
    )
    _require(
        identity.get("identity_rebind_or_cas_performed") is False
        and identity.get("central_36_identity_ledger_modified") is False
        and identity.get("store_identity_in_product_manifest") is None,
        "Identity or 36-owner ledger was mutated",
    )

    version = handoff.get("version_gate")
    _require(type(version) is dict, "Package Version gate missing")
    _require(
        version.get("authoritative_package_version") is None
        and version.get("status") == "HOLD_MISSING_AUTHORITATIVE_FOUR_PART_VERSION"
        and version.get("synthetic_or_self_asserted_version_accepted") is False,
        "Package Version must remain unauthenticated HOLD",
    )
    _require(
        version.get("export_file_version") == ""
        and version.get("export_product_version") == ""
        and version.get("product_manifest_package_version_gate") == "HOLD"
        and version.get("approved_identity_package_version_gate") == "HOLD",
        "version placeholders or gates changed",
    )

    physical_gate = handoff.get("physical_qa")
    _require(type(physical_gate) is dict, "local physical QA gate missing")
    _require(
        physical_gate.get("status") == "DEFERRED_LOCAL_GATE"
        and physical_gate.get("completed_sessions") == 0
        and physical_gate.get("required_sessions") == 6
        and physical_gate.get("captured_screenshots") == 0
        and physical_gate.get("required_screenshots") == 36
        and physical_gate.get("cloud_ci_counts_as_physical_qa") is False,
        "physical Windows QA cannot be promoted by cloud CI",
    )

    controls = handoff.get("controls")
    _require(type(controls) is dict, "safety controls missing")
    for key in (
        "package_build_allowed",
        "makeappx_pack_invoked",
        "product_msix_created",
        "product_msix_signed",
        "identity_cas_invoked",
        "package_version_written",
        "central_36_ledger_modified",
        "partner_center_written",
        "store_submission_allowed",
        "store_published",
        "sale_ready",
        "second_3d_product_allowed",
    ):
        _require(controls.get(key) is False, "forbidden promotion/action: " + key)

    return {
        "status": "CURRENT_SOURCE_PACKAGE_HANDOFF_VERIFIED_NOT_PRODUCT",
        "source_sha": SOURCE_SHA,
        "request_id": REQUEST_ID,
        "factory_artifact_id": FACTORY_ARTIFACT_ID,
        "factory_zip_sha256": FACTORY_ZIP_SHA256,
        "qa_pr19_head": QA_PR19_HEAD,
        "qa_pr20_head": QA_PR20_HEAD,
        "registration_type": REGISTRATION_TYPE,
        "package_build_allowed": False,
        "identity_rebind": "HOLD",
        "authoritative_package_version": "HOLD",
        "official_store_assets": "HOLD",
        "physical_windows_qa": "DEFERRED_LOCAL_GATE",
        "sale_ready": False,
        "store_submission_allowed": False,
    }
