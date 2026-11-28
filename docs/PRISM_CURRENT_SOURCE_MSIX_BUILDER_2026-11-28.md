# Prism Route 3D — current-source fail-closed MSIX builder

This PR is stacked on the exact Repository-Provisioner-3D PR #10 HEAD
894775ae23cb5c8a6daca959b04804918ec255b9. It does not edit PR #9's historical
handoff, the central 36-owner Identity/Version ledger, Factory source, or
Partner Center.

## Fixed product tuple

- Factory PR #25 source/build HEAD:
  b03ce7b16c3f75c04fe20fdda224c45849eeba0d
- Request: 3d-prism-route-3d-b03ce7b16c3f
- Factory artifact: 14797309778; ZIP SHA-256:
  e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac
- EXE SHA-256:
  66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13
- PCK SHA-256:
  b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666
- Independent QA PR #19 HEAD:
  9b90bfc9dfa6ded9699c3f22df45390be909dae8
- QA-only package preflight PR #20 HEAD:
  31032210446e5de7376a82698d854d25a51da2f9
- Durable QA custody artifact #15233410594, SHA-256:
  a02ed2a03ef37ebdb4dc46ad31c84148da3949fb1e55c5b0e0ae3627769f1b9f
  (167,283,608 bytes; expires 2026-12-27 21:39:58 UTC).

The builder recovers the original Factory ZIP from that QA-owned custody
artifact and rechecks the outer ZIP, original Factory ZIP, exact three-member
set, EXE, PCK and export manifest. It does not silently rebuild or substitute
another source revision.

## Three mandatory approvals before any product MSIX

1. **Current-source official Identity:** Partner Center official UI return
   must be approved, carry the exact source SHA/request/artifact/EXE/PCK
   binding, and explicitly record verified current-source Identity rebind/CAS.
   Historical 15fd/e432 Identity values are not accepted.
2. **Authoritative four-part Package Version:** must come from the same
   official Identity return. The Version receipt pins the exact raw Identity
   return SHA-256 and repeats the Publisher, PFN, Store ID and Package SID.
   Self-asserted or synthetic Version values are rejected.
3. **User-approved Store PNG bytes:** all three required PNGs must have an
   explicit approval receipt and independently matching dimensions, PNG
   chunk CRCs, whole-file CRC32 and SHA-256:
   - Assets/StoreLogo.png — 50×50
   - Assets/Square150x150Logo.png — 150×150
   - Assets/Square44x44Logo.png — 44×44

The package binding and AppxManifest are checked against the official
Identity/Version return. Publisher, PFN, Package SID, Store ID, source/request,
EXE/PCK, assets, MakeAppx signature/hash, and manifest mapping must all match.
The EXE and external PCK remain side-by-side under
VFS/ProgramFilesX64/PrismRoute3D/.

## Workflow modes

- Pull requests always run **fixture-only** Windows tests. Synthetic bytes are
  test inputs only; the job never invokes MakeAppx pack or creates a product
  MSIX.
- Manual workflow_dispatch defaults to fixture-only.
- real-product-msix is a separate manual mode behind the
  prism-route-3d-msix-release GitHub Environment. It additionally requires
  environment variable PRISM_MSIX_BUILD_APPROVED=true and a read-only
  PRISM_QA_ARTIFACT_READ_TOKEN secret with actions:read on 3d-build-qa.
  Configure required reviewers on that environment before enabling the variable.
- The real mode fails closed if any approval file is absent or stale. It
  creates only an **unsigned** MSIX after all gates pass. It never signs,
  uploads to Partner Center, submits, publishes, or changes Identity/Version.

Expected approval bundle path (not present in this PR):

approvals/prism-route-3d/current-source-b03ce7b1/

- identity-return.json
- identity-capture-receipt.json (raw-byte SHA256 bound by identity-return.json)
- version-return.json
- package-binding.json
- asset-approval.json
- AppxManifest.xml
- Assets/StoreLogo.png
- Assets/Square150x150Logo.png
- Assets/Square44x44Logo.png

## Current result / explicit HOLDs

As of 2026-11-28, the approved current-source Identity return, authoritative
four-part Package Version and user-approved Store PNG bytes have not been
supplied. Therefore this PR's allowed path is fixture-only. No product MSIX
is created by this change.

Physical Windows gameplay QA remains 0/6 sessions and 0/36 screenshots;
cloud tests are not physical QA. Signing, real Store submission, publish,
sale-ready, and central 36-owner ledger writes remain out of scope and false.
