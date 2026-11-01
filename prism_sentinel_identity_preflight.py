"""Prism Sentinel pre-CAS structural preflight. Never grants Store or CAS approval.

All fields are pinned against independent Factory anchors. A self-declared Partner
Center capture is *not* authenticated by this module. No Store write occurs.
"""
from __future__ import annotations

SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
LEGACY_SOURCE = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
LEGACY_COMMIT = "11417b75636ee18816028ffd5221884c4c9a9836"
EXE = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK = "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"
ARCHIVE = "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c"
RETURN_TARGET = "products/prism-route-3d/store/approved-identity.json"
EXPECTED = {
    "product_name": "Prism Route 3D",
    "slug": "prism-route-3d",
    "source_sha": SOURCE,
    "request_id": REQUEST,
    "factory_build_head": SOURCE,
    "factory_run_id": 40901053437,
    "factory_artifact_id": 12909162367,
    "factory_archive_sha256": ARCHIVE,
    "exe_sha256": EXE,
    "pck_sha256": PCK,
    "registration_type": "MSIX_OR_PWA_GAME",
    "partner_center_selection": "MSIX or PWA game",
    "packaging_strategy": "GODOT_WINDOWS_EXE_PCK_TO_MAKEAPPX_STANDARD_MSIX",
    "artifact_role": "FACTORY_EXE_PCK",
    "identity_return_target": RETURN_TARGET,
}
IDENTITY_MATCH = {
    "product_name": "Prism Route 3D",
    "store_id": "9N95J2T57B41",
    "source_sha": SOURCE,
    "request_id": REQUEST,
    "factory_build_head": SOURCE,
    "factory_artifact_id": 12909162367,
    "factory_archive_sha256": ARCHIVE,
    "exe_sha256": EXE,
    "pck_sha256": PCK,
    "registration_type": "MSIX_OR_PWA_GAME",
    "partner_center_selection": "MSIX or PWA game",
    "identity_return_target": RETURN_TARGET,
    "evidence_origin": "partner_center_ui",
}
REQUIRED_IDENTITY_TEXT = (
    "reserved_display_name", "package_identity_name", "publisher",
    "publisher_display_name", "pfn", "package_sid", "capture_reference",
)
FORBIDDEN = (
    "version", "package_version", "inferred_version", "approved_version",
    "signed_product_msix", "store_submission_allowed", "cas_applied",
    "store_ready", "submission_authorized",
)

class PreflightError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise PreflightError(message)

def check(receipt, identity=None):
    """Check immutable source/artifact correlation, then HOLD for official CAS.

    A structurally complete positive identity fixture still returns HOLD.
    Authentication must occur independently in the approved local CAS writer.
    """
    require(type(receipt) is dict, "missing Factory receipt")
    for key, expected in EXPECTED.items():
        require(type(receipt.get(key)) is type(expected) and
                receipt[key] == expected, "Factory anchor mismatch: " + key)
    require(receipt.get("fixture_identity") is False and
            receipt.get("signature_present") is False and
            receipt.get("product_msix") is False, "fixture or package role promoted")
    require(not any(k in receipt for k in FORBIDDEN),
            "Version/Store authorization must not be inferred")
    status = "HOLD_OFFICIAL_IDENTITY_EVIDENCE_MISSING"
    if identity is not None:
        require(type(identity) is dict, "invalid Identity capture")
        require(not any(k in identity for k in FORBIDDEN),
                "Version/Store authorization must not be inferred")
        require(identity.get("historical_identity_commit") != LEGACY_COMMIT and
                identity.get("identity_return_commit") != LEGACY_COMMIT,
                "historical Identity return cannot bind Sentinel")
        for key, expected in IDENTITY_MATCH.items():
            require(type(identity.get(key)) is type(expected) and
                    identity[key] == expected, "Identity revision/Store mismatch: " + key)
        for key in REQUIRED_IDENTITY_TEXT:
            val = identity.get(key)
            require(type(val) is str and bool(val.strip()) and len(val) <= 512,
                    "missing official Identity field: " + key)
        require(identity["reserved_display_name"] == "Prism Route 3D",
                "reserved display name mismatch")
        require(identity.get("fixture_only") is False,
                "synthetic/fixture Identity cannot be approved")
        # Even a fully populated UI capture is not an authenticated CAS receipt.
        status = "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED"
    return {
        "status": status, "source_sha": SOURCE, "request_id": REQUEST,
        "factory_build_head": SOURCE, "factory_artifact_id": 12909162367,
        "factory_payload_structurally_correlated": True,
        "identity_fields_structurally_correlated": identity is not None,
        "official_partner_center_authenticated": False,
        "official_identity_cas_verified": False,
        "approved_version_verified": False,
        "signed_product_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "product_e2e": "HOLD", "store_submission_allowed": False,
        "local_windows_gate": "DEFERRED_LOCAL_GATE",
    }
