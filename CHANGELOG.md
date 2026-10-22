# Changelog

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
