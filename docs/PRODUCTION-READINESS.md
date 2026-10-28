# FEA v0.4.5 — stable scope and release evidence

FEA v0.4.5 is the first stable GitHub release of the dependency-free Node.js CLI. Stability applies to bounded Electron release-resource auditing and deterministic policy reporting. It does not turn every command in the repository into a production security guarantee.

## Stable commands

The supported v0.4.5 core is:

- `fea init`: create the versioned JSON configuration.
- `fea scan`: inspect a trusted, non-concurrently modified Electron resource directory.
- `fea asar-scan`: inspect a regular Electron ASAR using the standard Chromium Pickle header and bounded entry reads.
- `fea verify`: apply current policy to a complete report produced by the same FEA scanner version.
- `fea compare`: compare compatible complete reports.
- `fea sarif`: create sanitized SARIF with repository anchor locations.

The scanner fails closed on unsupported links and special files, malformed archives, incomplete reads, bounds violations, opaque text where inspection is required, changed inputs and configured resource limits. Reports use path identifiers and do not include candidate secret values or source excerpts.

## Install and uninstall

Requirements: Node.js 20 or later and npm. From a reviewed source checkout:

```sh
npm test
npm run distribution:smoke
npm pack --ignore-scripts
npm install -g ./marsbasex-fea-0.4.5.tgz
fea --help
```

Remove it with:

```sh
npm uninstall -g @marsbasex/fea
```

The distribution smoke test packs the allowlisted files with lifecycle scripts disabled, installs the tarball without registry access, checks the npm bin shim, then executes `init`, `scan` and `verify` against an owned clean fixture. It deletes the temporary installation and does not publish to npm.

## Required release evidence

The tagged commit must satisfy all of these checks:

1. `npm test` passes with no skipped or failing tests.
2. `npm run distribution:smoke` passes locally and in the Windows, macOS and Linux GitHub Actions matrix.
3. The native Electron workflow passes on Windows and macOS for the owned unsigned GUI fixture.
4. The package contains the CLI, documentation, Apache-2.0 license, changelog and security policy, and excludes tests, demos, credentials and source maps.
5. `package.json`, CLI help and `scannerVersion` all report `0.4.5`.
6. The GitHub Release is created from the exact commit that passed the checks and includes the npm tarball plus its SHA-256 checksum.

## Experimental commands

The following interfaces remain available for evaluation and keep their explicit experimental boundaries:

- `protect preview/apply/rollback`: bounded Forge JSON edits with hash-checked rollback. It requires Forge and `@electron-forge/plugin-fuses` 7.4 or later and still requires rebuild, functional tests, signing and final-artifact verification.
- `arena`: synthetic or externally supplied paired evidence; it does not establish real AI reverse-engineering resistance.
- `release publisher`, `release inspect`, `release manifest`, `signature`, `migrate`, `obfuscate` and `runtime`: evidence or suggestions within each guide's stated limits.
- MCP: read-only access to a precomputed sanitized report; the host model's privacy and trust are separate.

## Unassessed claims

The v0.4.5 release does not claim:

- that an application cannot be reverse engineered, modified or reimplemented;
- MSI, DMG or PKG payload and installer-action inspection;
- a successful positive path using an owned commercial Windows certificate or Apple Developer ID plus notarization;
- authenticated provenance for arbitrary imported JSON evidence;
- a measured reduction in real AI attack success against commercial applications;
- independent audit or security certification.

A valid signature does not encrypt client code. ASAR is an archive, not a confidentiality boundary. Server-side authorization remains necessary for sensitive online operations.
