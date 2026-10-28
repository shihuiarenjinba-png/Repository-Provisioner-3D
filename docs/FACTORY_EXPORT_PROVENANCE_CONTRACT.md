# GAME_3D Factory export provenance — pre-Identity byte contract

Status: **standalone verifier + offline adversarial tests**. Not yet wired into the Provisioner CLI or a real accepted product workflow. Do not report PRE_IDENTITY_READY=PASS until authenticated GitHub download and an accepted product path are exercised.

## Independent evidence

A local Godot EXE/PCK SHA-256 proves only the bytes built by the local Provisioner. A local JSON receipt is not independent evidence. The factory_export_evidence.verify_factory_export_artifact function requires a downloaded ZIP and **separately fetched GitHub Actions run and artifact API metadata**. The downloaded ZIP must match the GitHub artifact SHA-256.

## Artifact contract

The artifact must be named exactly godot-3d-factory-export-evidence and contain only export-evidence.json, candidate.exe, and optional candidate.pck. It must come from a completed successful Factory workflow dispatch/push on the pinned work branch. Template and non-product MakeAppx fixture artifacts are rejected.

The JSON has exactly these fields:

- schema_version: integer 1
- request_id, product_type = GAME_3D, source_repository, source_branch, source_sha, slug
- factory_build_head: 40-character commit SHA of the export workflow run
- exe_path = candidate.exe, exe_sha256, exe_size_bytes
- pck_path = candidate.pck or null, pck_sha256 and pck_size_bytes (both null when PCK is embedded)

The verifier rejects mismatched request/product/branch/SHA, mismatched factory_build_head versus GitHub workflow head_sha, expired or unsuccessful artifacts, digest mismatch, duplicate/extra/unsafe ZIP entries, and EXE/PCK byte or size mismatches. It compares against the local inspect_package(..., godot_export=True) result.

**Never overwrite source_sha with factory_build_head.** The former is the immutable product source correlation key; the latter is the subsequent Factory export/build commit. The caller must authenticate the GitHub API and artifact download; fabricated API metadata defeats independence.

## Evidence limits and remaining work

A successful result is PRE_IDENTITY_BYTES_CORRELATED with evidence_scope=FACTORY_ARTIFACT_BYTES_NOT_STORE_E2E. It is **not** Partner Center Identity, an approved/signed MSIX, MakeAppx product compatibility, Windows install, GPU, GUI, consumer QA or Store readiness.

Next: wire this verifier into the 3D-only Provisioner flow with an explicit Factory artifact URL/run ID, retrieve GitHub API metadata independently, and fail closed before official Identity if evidence is absent. Keep the 120-hour generation gate, active_product=null, and new_product_allowed=false unchanged. The Windows-all-auto scheduler, Identity queue and central QA backlog remain 36-minute ownership.
