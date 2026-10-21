# FEA v0.4.4 — Unified release audit (experimental)

One read-only command combines bounded format recognition, SHA-256 release-manifest pinning, optional native publisher verification, and imported scan/native build evidence. Each check returns **pass / fail / unassessed**, and the gate exits nonzero if any requirement fails or is unassessed.

## CLI

    node scripts/release-audit.mjs ./dist/Product.exe --out ./audit/release --expected-sha256 <TRUSTED_MANIFEST_SHA256> --thumbprint <EXPECTED_CERT_FINGERPRINT>

Optional arguments: --scan-report <FEA_JSON> and --native-report <NATIVE_JSON>. Results are release-audit.json and release-audit.md. Exit 0 means all checks pass; 2 means fail or unassessed; 1 means invalid input.

**The expected SHA-256 is FEA's canonical snapshotArtifact(file).snapshotSha256 from the previous fea release manifest, not raw sha256sum(file).** The pin must come from a protected release channel. Rehashing a possibly compromised binary and then using that new hash as its own proof does not establish integrity.

| Format | Recognized | Not inspected |
| --- | --- | --- |
| EXE | Basic PE DOS + NT signature and bounded offset | Whether it is an installer; embedded payload |
| MSI | CFB magic and selected compound-document header fields | MSI database, actions, digital signature |
| DMG | Trailing UDIF koly header/version/size | Disk image contents, Apple notarization |
| PKG | XAR magic/version and compressed TOC bounds | TOC, embedded scripts, signature |

Recognition does NOT mount, unpack, execute, or verify the safety of an installer. Unsupported formats are unassessed. Current native publisher checks apply only to Windows PE EXE with a pinned signing certificate. MSI, DMG and PKG publisher trust are unassessed. macOS .app codesign/Gatekeeper checks exist separately in the earlier release publisher command.

Imported scan/native reports are sanitized to selected fields only and are *not cryptographically authenticated*. A clean self-contained JSON report remains unassessed, while explicitly bad findings fail. The overall gate is intentionally conservative; unsigned fixtures and unattested reports cannot manufacture a fully trusted pass. Production pipelines must bind measurements to independently protected artifact digests and signed CI attestations.

## Reproduce

    npm test
    npm run trust:demo
    npm run release:audit-demo

The Linux/Windows/macOS CI matrix exercises owned synthetic fixtures and negative paths. No commercial signing credentials are committed and no positive signed-release test is claimed. Original assets/fea-icon.png is untouched.
