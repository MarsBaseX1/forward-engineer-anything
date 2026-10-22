# Release signing and distribution readiness

## Package-level supply-chain checks

The stable release workflow creates these assets from the exact npm tarball:

- `marsbasex-fea-X.Y.Z.tgz`: the distributable CLI package
- `npm-pack.json`: npm pack manifest and integrity metadata
- `sbom.spdx.json`: SPDX 2.3 software bill of materials, including SHA-256 hashes for packaged files
- `package-security-audit.json`: deterministic archive/content checks and the tarball SHA-256
- `SHA256SUMS.txt`: checksums covering the tarball and all metadata files

The package audit checks archive path containment, package-root layout, duplicate paths, links, required files, metadata/version consistency, install-time lifecycle scripts, runtime dependencies, common private/build artifacts, and high-confidence credential patterns. It emits an SPDX SBOM and a machine-readable report. Release verification independently checks the checksums, provenance attestations, the SBOM-to-tarball digest binding, and that the audit report is a PASS for the same tarball.

This is a supply-chain screening layer, not a malware verdict, a full source-code security review, or a guarantee that no secret can exist. Review any finding instead of treating a regex scan as proof of absence.

## Windows Authenticode

- Obtain an organization-appropriate code-signing certificate from a trusted provider, or enroll in a supported managed signing service.
- Keep private keys in a hardware-backed or managed signing boundary; never store certificate private keys in repository secrets as exported, unencrypted files.
- Sign the final EXE/MSI after packaging, then verify the signature, certificate chain, timestamp, and expected publisher identity on a clean Windows runner.
- Record the signed artifact's SHA-256 after signing. The signed bytes differ from the unsigned package, so attest and publish the final signed artifact, not an earlier build output.
- A valid signature identifies the publisher and protects integrity; it does not guarantee SmartScreen will show no warning or prove the program is safe.

## macOS Developer ID and notarization

- Enroll in the Apple Developer Program and obtain a Developer ID Application certificate for distribution outside the Mac App Store.
- Sign the final app and DMG/PKG with hardened runtime and the required entitlements; protect signing credentials in a restricted secret store.
- Submit the exact distributable to Apple's notarization service, wait for acceptance, staple the ticket where applicable, then verify with `codesign`, `spctl`, and `xcrun stapler validate` on a clean macOS runner.
- Record and attest the final notarized artifact's digest. Notarization is not a guarantee of malware-free software.

## Registry publication gate

Do not publish to npm automatically as a side effect of GitHub Release publication. Before enabling `npm publish`:

1. Confirm the exact package name, owner/organization access, package visibility, license, README links, and intended public API.
2. Prefer npm trusted publishing with GitHub Actions OIDC if the package and account support it; avoid long-lived automation tokens where possible.
3. Require successful cross-platform tests, the exact-tarball package audit, SBOM validation, and provenance checks before publication.
4. Publish only the exact tarball that was verified, then install the registry-resolved version in a clean consumer and compare its integrity with the approved tarball.
5. Treat publishing a new version as an irreversible public distribution decision; never overwrite or silently replace a released version.

## Current boundary

The GitHub Release and GitHub build-provenance attestations do not constitute Windows Authenticode signing, macOS Developer ID signing/notarization, npm Registry publication, or formal security certification. Those are separate distribution channels with their own credentials, verification requirements, and release approvals.
