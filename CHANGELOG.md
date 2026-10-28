# Changelog

## 0.4.5 — 2026-10-28

### Stable scope

- Publish the dependency-free `fea` CLI for bounded Electron resource-directory and standard ASAR inspection, sanitized JSON/SARIF output, deterministic comparison and policy gates.
- Verify the npm tarball allowlist, offline installation, CLI shim, scan and policy gate on Windows, macOS and Linux CI.

### Fixed

- Parse the standard Chromium Pickle header used by Electron ASAR archives; owned fixtures now emit the same header layout.
- Generate Forge 7.4+ Fuses plugin configuration with the supported `{ name, config }` object and Fuse v1 wire indexes while preserving unrelated fuse choices.
- Reject Protect previews when the required `@electron-forge/plugin-fuses` dependency is absent or unsupported.
- Reject policy verification of reports created by a different FEA scanner version.

### Boundaries

- Protect, Arena, native publisher verification and unified release audit remain experimental.
- MSI / DMG / PKG payload inspection, positive validation with commercial signing identities and real AI reverse-engineering resistance remain unassessed.
- This release does not claim that software is impossible to inspect, modify or reimplement.

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
