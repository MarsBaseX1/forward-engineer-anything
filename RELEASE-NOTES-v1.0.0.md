# FEA v1.0.0 — First Stable Release

**Build forward. Raise the cost of reverse engineering.**

FEA (Forward Engineer Anything) is now a stable open-source protection engineering framework for Electron desktop applications. It helps teams reduce unnecessary asset exposure before shipping, enforce CI policy gates, plan and apply bounded hardening, and compare results.

This is the counterpart to post-release analysis tools such as REA: FEA works at the **build and delivery stage**.

## What is stable in v1.0.0

- **Audit rules FEA001–FEA009** covering source maps, private-key markers, internal configuration, debug/test assets, client-side authorization judgments, hardcoded secrets, unobfuscated business-logic indicators, and client-side sensitive data exposure.
- Bounded directory and ASAR scanning with policy verification and CI gating.
- Controlled Electron Forge JSON automation (`protect` command) for enabling ASAR packaging plus recommended integrity Fuses (`EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`), with external backups and exact rollback.
- Suggestion generators: `migrate` (server-authoritative patterns), `obfuscate`, and `runtime`.
- Arena paired evaluation protocol with local trusted adapter executor and external JSONL evidence import.
- SARIF 2.1.0 export for GitHub Code Scanning.
- Release readiness, publisher trust status checks, and unified release audit for bounded installer recognition.
- Production-readiness CLI distribution smoke tests.
- Release SHA-256 checksums and GitHub build-provenance attestations for the npm package and release metadata.

## Honest boundaries

- Does **not** claim that shipped client code cannot be reverse engineered or modified.
- ASAR is packaging, not encryption.
- Does not automatically rewrite application code or execute untrusted project configurations.
- Arena results and suggestions do not prove reverse-engineering resistance.
- Installer content parsing and real commercial certificate positive verification remain limited.
- Build provenance helps verify where a specific release asset came from; it is not a malware scan, code-signing certificate, or security certification.

See [ANTI-REA-HARDENING.md](docs/ANTI-REA-HARDENING.md), [release asset verification](docs/RELEASE-VERIFICATION.md), and [CHANGELOG.md](CHANGELOG.md) for full details.

## Get started

```bash
git clone https://github.com/MarsBaseX1/forward-engineer-anything.git
cd forward-engineer-anything
npm test
npm run demo
npm run demo:check
```

Requires Node.js 20+. No additional npm dependencies for the scanner and demo.

---

*Apache-2.0. Independent of REA and Trivy.*
