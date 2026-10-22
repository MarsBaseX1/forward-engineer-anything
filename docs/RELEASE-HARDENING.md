# FEA release hardening gate

This gate adds stricter package-content checks and platform-native publisher verification. It does not publish to npmjs.org, sign files on behalf of a certificate owner, or claim a security certification.

## npm package content audit

Before creating a draft GitHub Release, the release workflow runs the package inspector against the generated npm TAR. It reads the gzip/TAR stream directly; it does not extract or execute the package.

The inspector bounds compressed and expanded size, file count, path depth and per-file size; validates TAR checksums; rejects path traversal, absolute paths, symlinks, hard links, special files, duplicate/case-colliding paths and unsafe modes; compares the actual files and sizes with npm's pack manifest; verifies SHA-1/SHA-512 integrity; checks package metadata, lifecycle hooks and runtime dependencies; and looks for executable payloads, sensitive file types, high-confidence credential patterns and active/remote SVG content.

The audit is heuristic. It cannot prove that a package contains no secret or malware. It does not scan transitive dependencies; the current package policy rejects runtime dependencies.

The independent release workflow repeats this audit against the actual downloaded TAR, not the build workspace, before it can publish a draft Release.

## Native Windows and Apple artifacts

If a GitHub Release includes an EXE or MSI, a Windows-hosted job checks the downloaded file's SHA-256 against GitHub's asset digest and runs Windows Authenticode verification. It requires the signer certificate thumbprint to match the configured pin.

If a Release includes a DMG or PKG, a macOS-hosted job checks the SHA-256 against GitHub's asset digest and requires a valid platform signature, the configured Apple Team ID, Gatekeeper acceptance, and a valid stapled notarization ticket.

Configure these GitHub Actions secrets before attaching corresponding native assets:

- **FEA_WINDOWS_SIGNER_THUMBPRINT**: the expected Authenticode certificate SHA-1 thumbprint, 40 hexadecimal characters.
- **FEA_MAC_TEAM_ID**: the expected Apple Developer Team ID, 10 uppercase letters/digits.

These values pin the expected publisher; they are **not signing private keys**. This workflow verifies signatures and notarization of already-built artifacts. It does not issue certificates, sign builds, submit binaries to Apple's notary service, or manage a commercial signing provider. Keep signing keys and notarization credentials in a protected signing service or environment, not in the repository.

When no native installers are attached, the platform jobs report that the checks are not applicable to the current CLI-only release. If a native asset is attached and the corresponding pin is missing, the job fails and blocks publication.

## Scope and remaining boundary

- The published v1.0.0 Release is a JavaScript/npm TAR, not a Windows or macOS installer. Its release assets are verified with SHA-256 and GitHub build-provenance attestations.
- The npm TAR is inspected without extraction or execution. Native EXE/MSI/DMG/PKG assets receive digest and publisher/notarization checks, but this gate does **not** unpack arbitrary installer payloads or claim to have inspected every file inside them.
- The existing native Electron CI builds a real fixture on Windows and macOS and checks its packaged metadata, ASAR/Fuses and GUI startup. Those build-fixture checks are separate from installer payload extraction.
- Before shipping an actual desktop installer, add a format-specific, non-executing payload inspection adapter for the exact installer technology. Generic EXE installers do not have one universal safe extraction format.
- This workflow does not run npm publish. npm Registry publication should be a separately approved stage with npm trusted publishing/OIDC, package ownership verification, provenance verification, and an explicit maintainer action.
