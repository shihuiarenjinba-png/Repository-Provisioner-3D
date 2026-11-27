# Prism Route 3D — current-source package-readiness handoff

This is a new, append-only current-source handoff. It is intentionally stacked
on the existing historical Sentinel handoff PR #9; PR #9 and its e432/15fd
receipts are not rewritten.

## Pinned current product tuple

- Factory: `shihuiarenjinba-png/3d-game-factory`
- Factory PR: #25
- Exact source / build HEAD:
  `b03ce7b16c3f75c04fe20fdda224c45849eeba0d`
- Request: `3d-prism-route-3d-b03ce7b16c3f`
- Factory export run: `43794658086` (Godot 4.3, SUCCESS)
- Factory artifact: `14797309778`
- Factory ZIP SHA-256:
  `e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac`
- EXE SHA-256:
  `66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13`
- PCK SHA-256:
  `b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666`
- Export manifest SHA-256:
  `442d2c9070e017adf1c0ceaa96ba607f470c0f147176671f8a844122aca4d5bd`

The original Factory artifact has a retention deadline of
2026-11-30 07:32:37 UTC. Before that deadline, 3d-build-qa PR #20 downloaded
and reverified the exact Factory metadata, ZIP, three-member set, CRC, EXE,
PCK and export manifest. It preserved the original Factory ZIP byte-for-byte
inside QA-owned artifact #15233410594 (167,283,608 bytes; SHA-256
`a02ed2a03ef37ebdb4dc46ad31c84148da3949fb1e55c5b0e0ae3627769f1b9f`),
which expires 2026-12-27 21:39:58 UTC. The same QA artifact also preserves the
original PR19 physical handoff ZIP and its custody receipt. This is durable
QA evidence, not a product package.

## Independent QA and MakeAppx

- 3d-build-qa PR #19 exact HEAD:
  `9b90bfc9dfa6ded9699c3f22df45390be909dae8`
- PR #19 cloud workflows: 8/8 SUCCESS.
- Physical Windows QA: 0/6 sessions, 0/36 screenshots. Still HOLD.
- QA-only package preflight PR #20 exact HEAD:
  `31032210446e5de7376a82698d854d25a51da2f9`
- PR #20 base: exact PR #19 HEAD above.
- PR #20 workflows: 9/9 SUCCESS; package contract suite ran 12 tests on
  Windows and Ubuntu.
- QA custody artifact #15233410594 preserves exact Factory and physical
  handoff ZIP bytes.
- Read-only MakeAppx capability artifact #15233068292 (732 bytes; SHA-256
  `aaf107e7dee1d07da923d57dfeae435ce198ef5581e158e1c86765df261a7f87`).

MakeAppx was located at:

`C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\MakeAppx.exe`

- File version: `10.0.26100.9457 (WinBuild.160101.0800)`
- SHA-256:
  `58d5e69fd0322f960afbe34afed0eda66a5d001811ee838d1c7165130c3d55e5`
- Authenticode: Valid, Microsoft Corporation
- Runner image: `win25-vs2026`
- Only the no-argument usage/help probe ran. No `makeappx pack`, package
  creation, signing, or submission ran.

## Package mapping and unresolved inputs

Registration remains exactly `MSIX_OR_PWA_GAME` / Partner Center
“MSIX or PWA game”. GDK, `MSIX_OR_PWA_APP`, and
`EXE_OR_MSI_APP` are not accepted for this handoff.

The proposed payload mapping keeps the external PCK beside the executable:

- `candidate.exe` →
  `VFS/ProgramFilesX64/PrismRoute3D/candidate.exe`
- `candidate.pck` →
  `VFS/ProgramFilesX64/PrismRoute3D/candidate.pck`

The package layout is a deterministic proposal, not a generated AppxManifest
or an MSIX. Three standard Store image destinations are identified, but the
current product tree has no source assets at the checked `assets` or
`store/assets` paths. No placeholders or fabricated assets are accepted.

## Fail-closed gates

- Current-source Identity rebind: HOLD. The old Identity provenance is
  historical-only and is not bound to source b03ce7b1.
- Authoritative four-part Package Version: HOLD; no value is supplied.
  Export file/product version fields are empty.
- Official Store assets: HOLD; source paths are absent.
- Signing and real MSIX: not performed.
- Physical Windows GUI/gameplay QA: DEFERRED_LOCAL_GATE, 0/6 and 0/36.
- Store submission, publish, sale-ready, second product: false.

The contract and tests in this PR validate the pinned tuple and reject stale
source/request/artifact values, incorrect registration routes, fabricated
assets, unauthenticated Version, historical Identity promotion, MakeAppx
pack invocation, physical-QA promotion, and product MSIX/signing/submission.

No current-source Identity CAS or Package Version write is attempted. The
central 36-owner ledger and Partner Center are untouched.
