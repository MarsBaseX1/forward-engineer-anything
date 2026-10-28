# FEA v1.0.1 — Release integrity and supply-chain audit

**Build forward. Verify what you ship.**

FEA v1.0.1 strengthens the integrity and traceability of the CLI distribution and fixes release-blocking compatibility defects in the Electron ASAR and Forge Fuses paths.

## What's new

- **Package archive audit:** checks archive path containment, duplicate paths, links, required distribution files, package metadata/version, install-time lifecycle scripts, runtime dependency policy, unexpected development files, and high-confidence credential patterns.
- **SPDX 2.3 SBOM:** records the package identity and SHA-256 digests for files included in the exact npm tarball.
- **Digest-bound audit report:** produces `package-security-audit.json` with a PASS/FAIL result and the SHA-256 of the audited tarball.
- **Five release assets:** the tarball, npm pack manifest, SPDX SBOM, package audit report, and SHA-256 checksum list.
- **Independent verification:** checks checksums, npm package metadata and file manifest, build-provenance attestations, SBOM/audit digest binding, and a clean consumer install with CLI smoke tests.
- **Standard Electron ASAR compatibility:** parses Chromium Pickle headers emitted by standard Electron tooling.
- **Valid Forge Fuses automation:** emits Forge 7.4+ `{ name, config }` plugin configuration, preserves unrelated fuse choices and fails closed when the plugin dependency is missing.
- **Version-bound reports:** keeps the CLI/package/scanner version aligned and rejects policy verification or comparison across incompatible scanner versions.
- **Security reporting:** adds a public security policy and complete npm repository metadata.

## Download assets

- `marsbasex-fea-1.0.1.tgz`
- `npm-pack.json`
- `sbom.spdx.json`
- `package-security-audit.json`
- `SHA256SUMS.txt`

## Important boundaries

- A passing package audit is static supply-chain screening, not a malware verdict or a complete security audit.
- GitHub build-provenance attestations do not replace Windows Authenticode signing, macOS Developer ID signing/notarization, or SmartScreen reputation.
- npm Registry publication remains a separate, deliberate action; this release workflow does not publish to npm automatically.
- FEA does not claim that client-side code is impossible to reverse engineer.

See [release verification](docs/RELEASE-VERIFICATION.md), [release signing readiness](docs/RELEASE-SIGNING-READINESS.md), and [CHANGELOG.md](CHANGELOG.md).

Apache-2.0.
