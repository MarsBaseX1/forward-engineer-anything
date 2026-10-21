# Changelog

## 0.4.2-alpha.1 — 2026-10-21

### Added
- **FEA009**: Client-side sensitive data exposure (window.__STATE__, __APOLLO_STATE__, localStorage token patterns).
- Migration suggestions for FEA006 / FEA007 (`fea migrate`).
- Obfuscation suggestions for FEA001 / FEA008 (`fea obfuscate`).
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
