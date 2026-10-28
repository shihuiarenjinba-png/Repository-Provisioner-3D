"""Fail-closed Partner Center registration routing and USER_ID_REQUEST for GAME_3D.

Intermediate Godot .exe is NOT an EXE_OR_MSI_APP. Routing uses the final
Windows packaging strategy and verified pre-Identity provenance. This module
never queries Partner Center or invents official Store Identity values.
"""
from __future__ import annotations
import re
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
REQUEST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$")
SLUG = re.compile(r"^[a-z][a-z0-9-]{3,39}$")
STANDARD = "GODOT_WINDOWS_EXE_PCK_MAKEAPPX_MSIX"
GDK = "GDK_MICROSOFTGAME_CONFIG_MSIXVC"
BASE_FIELDS = (
    "Store ID", "reserved display name", "Package Identity Name",
    "Publisher", "Publisher Display Name", "PFN", "Package SID",
)
XBOX_FIELDS = ("Xbox Title ID", "SCID", "MSA App ID")


def registration_type(strategy: str, *, builder: str,
                      output_kind: str, gdk_config: bool) -> dict:
    """Require evidence of the final Store packaging strategy, not EXE inputs."""
    if (strategy == STANDARD and builder == "Windows SDK MakeAppx"
            and output_kind.lower() in {"msix", "appx"} and gdk_config is False):
        return {"status": "RESOLVED", "registration_type": "MSIX_OR_PWA_GAME",
                "partner_center_selection": "MSIX or PWA game"}
    if (strategy == GDK and builder == "Microsoft GDK"
            and output_kind.lower() == "msixvc" and gdk_config is True):
        return {"status": "RESOLVED", "registration_type": "GDK_GAME",
                "partner_center_selection": "GDK game"}
    return {"status": "HOLD_REGISTRATION_TYPE_UNRESOLVED",
            "registration_type": None, "partner_center_selection": None}


def user_id_request(job: dict, evidence: dict, *,
                    strategy: str, builder: str, output_kind: str,
                    gdk_config: bool) -> dict:
    """Return only requested field names after genuine PRE_IDENTITY_BYTES_CORRELATED.

    No identity value is inferred, and no fixture may be promoted to product.
    """
    route = registration_type(strategy, builder=builder,
                              output_kind=output_kind, gdk_config=gdk_config)
    if route["status"] != "RESOLVED":
        return {**route, "user_id_request": "まだ不要"}
    required = ("request_id", "source_sha", "slug", "display_name", "source_branch")
    if (not isinstance(job, dict) or not isinstance(evidence, dict)
            or any(not isinstance(job.get(k), str) or not job[k] for k in required)
            or not REQUEST.fullmatch(job["request_id"])
            or not SHA40.fullmatch(job["source_sha"])
            or not SLUG.fullmatch(job["slug"])
            or not job["source_branch"].startswith("codex/")
            or job.get("product_type") != "GAME_3D"
            or evidence.get("status") != "PRE_IDENTITY_BYTES_CORRELATED"
            or evidence.get("evidence_scope") != "FACTORY_ARTIFACT_BYTES_NOT_STORE_E2E"
            or any(evidence.get(k) != job[k] for k in ("request_id", "source_sha", "slug"))
            or not isinstance(evidence.get("factory_build_head"), str)
            or not SHA40.fullmatch(evidence["factory_build_head"])
            or type(evidence.get("workflow_run_id")) is not int
            or type(evidence.get("artifact_id")) is not int
            or evidence["workflow_run_id"] <= 0 or evidence["artifact_id"] <= 0):
        return {**route, "status": "HOLD_PRE_IDENTITY_NOT_READY",
                "user_id_request": "まだ不要"}
    return {**route, "status": "USER_ID_REQUEST",
            "product_name": job["display_name"],
            "slug": job["slug"], "request_id": job["request_id"],
            "source_sha": job["source_sha"],
            "factory_build_head": evidence["factory_build_head"],
            "required_partner_center_fields": list(BASE_FIELDS + (XBOX_FIELDS if route["registration_type"] == "GDK_GAME" else ())),
            "identity_values": None,
            "post_identity_ready": False,
            "windows_install_gpu_gui": "DEFERRED_LOCAL_GATE"}
