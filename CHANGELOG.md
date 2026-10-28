# Changelog

## 1.0.1 — 2026-10-28

### Release integrity and supply-chain audit

- Add package-level archive safety checks for path traversal, duplicate entries, links, unexpected files, install-time lifecycle scripts, and common credential patterns.
- Generate an SPDX 2.3 SBOM with SHA-256 hashes for files included in the npm tarball.
- Bind the machine-readable package audit report and SBOM to the exact tarball SHA-256 digest.
- Extend GitHub release assets with the SBOM and audit report; checksum and attest all five assets.
- Independently verify the SBOM and audit digest against the downloaded tarball before the release can be promoted.
- Document Windows Authenticode, macOS Developer ID/notarization, and registry publication as separate release gates.

### Compatibility and correctness fixes

- Parse the standard Chromium Pickle header used by Electron ASAR archives; owned fixtures now emit the same header layout.
- Generate the supported Forge 7.4+ Fuses plugin `{ name, config }` object using Fuse v1 wire indexes while preserving unrelated fuse choices.
- Reject Protect previews when `@electron-forge/plugin-fuses` 7.4 or later is not declared.
- Keep `package.json`, the CLI banner and report `scannerVersion` aligned at `1.0.1`; reject verification or comparison of reports from an incompatible scanner version.
- Add complete npm metadata, a security policy and generated-output ignore rules; exclude internal historical design notes from the installable package.

**Boundaries:** These checks improve release traceability but are not a malware verdict, a complete vulnerability audit, a security certification, Windows Authenticode signing, or macOS notarization.


## 1.0.0 — 2026-10-21

### First stable release

FEA is now a complete anti-REA hardening framework for Electron desktop applications.

**Core capabilities (stable):**
- Rules FEA001–FEA009 covering source maps, private keys, internal config, debug/test assets, client-side authorization, hardcoded secrets, unobfuscated logic, and client-side sensitive data exposure.
- Bounded ASAR scanning and directory scanning with policy verification and CI gating.
- Controlled Electron Forge JSON automation (`protect` command) for `asar: true` + recommended integrity Fuses (`EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`) with exact rollback and external backups.
- Suggestion generators: `migrate` (server-authoritative authorization), `obfuscate`, and `runtime`.
- Arena paired evaluation protocol with local trusted adapter executor, import of external JSONL evidence, and synthetic demo fixtures.
- SARIF 2.1.0 export for GitHub Code Scanning.
- Release readiness, trust checks (Authenticode / codesign status), and unified release audit for bounded installer recognition.
- Production-readiness CLI distribution acceptance (offline install + scan + policy verify).

**Honest boundaries remain:**
- Does not claim software is un-reverse-engineerable.
- Does not automatically rewrite code or execute untrusted configs.
- Arena results and suggestion generators do not prove resistance to reverse engineering.
- Installer content parsing and real commercial certificate positive verification remain limited.

See [ANTI-REA-HARDENING.md](docs/ANTI-REA-HARDENING.md) and [ROADMAP.md](docs/ROADMAP.md).

## 0.4.5-rc.1 — 2026-10-21

- Production-readiness CLI distribution acceptance.
- Mandatory v1 production gates documented.

## 0.4.4 — 2026-10-21

- Unified release audit with bounded installer recognition and fail-closed trust results.

## 0.4.3 — 2026-10-21

- Release manifest and native publisher trust checks.

## 0.4.2-alpha.1 — 2026-10-21

### Added
- **FEA009**: Client-side sensitive data exposure (window.__STATE__, __APOLLO_STATE__, localStorage token patterns).
- Migration suggestions for FEA006 / FEA007 (`fea migrate`).
- Obfuscation suggestions for FEA001 / FEA008 (`fea obfuscate`).
- Runtime protection suggestions (`fea runtime`).
- Anti-REA Arena suite and `demo/rea-observer.mjs` adapter skeleton.
- Electron Fuses automation in `protect` (EnableEmbeddedAsarIntegrityValidation + OnlyLoadAppFromAsar).

### Changed
- Default policy now blocks FEA001–FEA009.
- Demo baseline plants additional anti-REA findings.

### Notes
- All new capabilities remain experimental. Findings and suggestions do not prove reverse-engineering resistance.

## 0.4.1-alpha.1 — 2026-10-21

### Added
- FEA006, FEA007, FEA008 rules for client authorization, hardcoded secrets, and unobfuscated logic.

## 0.4.0-alpha.1 — earlier

- Experimental Forge JSON patch / rollback for ASAR setting.
- See IMPLEMENTATION.md for prior history.
