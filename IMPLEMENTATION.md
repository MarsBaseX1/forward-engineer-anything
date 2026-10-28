# FEA v1.0.1 — Implementation Guide

**Stable release (2026-10-28).** FEA is a protection engineering framework for Electron desktop applications. It raises the cost of REA-style reverse engineering and tampering through pre-release auditing, CI gating, controlled hardening, and comparison. It does **not** claim software is un-reverse-engineerable.

See [CHANGELOG.md](CHANGELOG.md), [ANTI-REA-HARDENING.md](docs/ANTI-REA-HARDENING.md), and [ROADMAP.md](docs/ROADMAP.md).

## Stable capabilities

| Capability | Command / entry | Notes |
|------------|-----------------|-------|
| Audit rules FEA001–FEA009 | `scan`, `asar-scan` | Directory and bounded ASAR |
| Policy verification | `verify` | CI fail-closed gating |
| Before/after compare | `compare` | JSON + Markdown |
| Forge automation | `protect preview/apply/rollback` | ASAR + integrity Fuses, external backup |
| Suggestions | `migrate`, `obfuscate`, `runtime` | Does not rewrite code |
| Arena | `arena compare/execute/import` | Trusted local adapter only |
| SARIF | `sarif` | GitHub Code Scanning compatible |
| Release checks | `release *` | Bounded; unassessed when evidence missing |

## Quick start

```bash
node src/cli.mjs --help
npm test
npm run demo && npm run demo:check
```

```bash
node src/cli.mjs init --out my-fea.json
node src/cli.mjs scan ./my-electron-resources --config my-fea.json --out ./audit
node src/cli.mjs verify ./audit/report.json --policy my-fea.json
```

Requires Node.js 20+. Scanner and demo have no install-time npm dependencies.

## Honest boundaries

- Client-distributed code can still be reverse engineered or modified.
- ASAR is packaging, not encryption.
- Does not automatically rewrite application code or execute untrusted project configs.
- Arena results and suggestions do not prove reverse-engineering resistance.
- Installer content parsing and real commercial certificate positive verification remain limited.
- No independent security audit or certification is claimed.

## Historical notes

Earlier experimental stages (v0.1–v0.4) added resource scanning, bounded ASAR, Forge planning/patching, Arena protocol, SARIF, release trust checks, and native packaging verification. Those capabilities are now part of the stable v1.0.0 surface, subject to the boundaries above.

For detailed threat model and future plans, see [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [ROADMAP.md](docs/ROADMAP.md).
