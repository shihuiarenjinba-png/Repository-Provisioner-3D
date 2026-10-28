# GAME_3D Factory export provenance — pre-Identity byte contract

Status: **real Prism Route 3D canary under CI verification**. This contract is wired into the Provisioner CLI and live GitHub Actions workflow. It does not establish Store Identity, product MSIX, installability or E2E PASS.

## Immutable canary

- Product: Prism Route 3D; slug: `prism-route-3d`
- source_branch: `codex/3d-canary-prism-route-20261028`
- source_sha: `15fdcb52e46e35e6de8e87c55af99719c21e09b9`
- request_id: `3d-prism-route-3d-15fdcb52e46e`
- Factory export run: `40640951915`; artifact: `12795476435`
- Packaging: Godot Windows EXE/PCK → Windows SDK MakeAppx → ordinary MSIX; registration_type=`MSIX_OR_PWA_GAME`, Partner Center selection=`MSIX or PWA game`
- No second 3D product before 48-minute supervisor approval of this one-canary PRE_IDENTITY rotation.

## Authenticated Factory bytes are canonical

The Provisioner independently fetches successful GitHub Factory workflow metadata and artifact metadata using authenticated `gh api`, downloads the exact artifact, checks the ZIP size and GitHub artifact SHA-256, then validates `export-evidence.json`, the exact run/branch/build HEAD, request/source/slug, and actual EXE/PCK sizes and SHA-256. The artifact name must be `godot-3d-factory-export-evidence`; template and non-product fixture artifacts are rejected.

The downloaded ZIP must contain exactly `export-evidence.json`, `candidate.exe`, and optional `candidate.pck`. Duplicate, unexpected, encrypted, unsupported, symlinked, oversized and corrupt members are rejected. The extracted Factory EXE is checked as a Windows x64 PE32+ binary; the PCK is checked for its `GDPC` header. The verifier checks the Factory EXE/PCK against the manifest **and** the independent GitHub API run/artifact metadata.

Godot 4.3 may assign a different PackedScene UID when a pinned project is imported again in a fresh workspace. The independent local re-export EXE must still match the Factory EXE in SHA-256 and size, and local/Factory PCK presence must match. A local PCK SHA difference is recorded as `local_reexport_pck_matches_factory=false` but is not silently substituted into the package. **Only the authenticated, verified Factory EXE/PCK are the canonical bytes for downstream packaging.** This avoids bypassing byte checks or accepting a nondeterministic local PCK as an equivalent payload.

Evidence fields include `payload_authority=AUTHENTICATED_FACTORY_ARTIFACT`, `canonical_package_path`, independent `source_sha` and `factory_build_head`, and Factory EXE/PCK SHA-256. The Provisioner re-inspects the canonical payload and checks hashes before the Identity step. If any required evidence is missing, HOLD before Identity lookup.

## Registration and operator handoff

A passing authenticated PRE_IDENTITY_BYTES_CORRELATED receipt with `evidence_scope=FACTORY_ARTIFACT_BYTES_NOT_STORE_E2E` permits `USER_ID_REQUEST` for the one fixed product. Required operator-supplied Partner Center fields: Store ID, reserved display name, Package Identity Name, Publisher, Publisher Display Name, PFN, Package SID. No GDK/Xbox fields for ordinary MakeAppx MSIX. Never infer identity values or query Partner Center in this lane.

Identity return target: `products/prism-route-3d/store/approved-identity.json` on the pinned Factory work branch, after independent official evidence validation and human authorization. This is not an instruction to write the file now. Post-Identity signed product MSIX and Windows-all-auto intake remain separate gates under 36-minute ownership.

## Safety and remaining gates

- Source SHA and request ID are immutable. Do not overwrite `source_sha` with `factory_build_head`.
- No Identity value, signature, product MSIX, GPU, Windows install, GUI or Store submission is asserted by PRE_IDENTITY.
- Local Windows tests are `DEFERRED_LOCAL_GATE` until the user explicitly resumes them.
- Existing 3d-build-qa ZIP/CRC/BlockMap/XML/manifest/payload guards remain mandatory for the eventual product MSIX.
- Keep Draft PRs unmerged; no main/release writes, force push, Store upload, or mass production.
