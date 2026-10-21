# FEA — Release candidate and production acceptance criteria

FEA is moving away from open-ended prototype development. **The currently supported production-candidate scope is a dependency-free Node.js CLI for Electron release-resource inspection and deterministic policy reporting.** No single security tool can prevent all reverse engineering. Treat production validation as a reproducible release decision, not a marketing claim.

## Install / uninstall rehearsal

Requirements: Node.js >=20 and npm. Run inside a trusted clone:

```sh
npm test
npm run distribution:smoke
```

The offline test runs `npm pack` with lifecycle scripts disabled, checks the published-file allowlist, installs that tarball into a new temporary directory without network access, checks the npm bin shim, then executes `fea init`, `fea scan` and `fea verify`. It deletes the temporary installation. It does **not** publish to npm, install global packages, execute third-party software, or validate publisher signatures.

For a local manual installation of a reviewed tarball: `npm install -g ./marsbasex-fea-<version>.tgz`; uninstall via `npm uninstall -g @marsbasex/fea`. Check the exact filename from `npm pack --json` rather than guessing it.

## Release criteria

All criteria below must be explicitly satisfied before a **stable v1.0.0** or any production-security claim:

1. **Cross-platform CI:** Windows/macOS/Linux unit and offline install smoke tests must pass on a fixed Git commit and Node LTS. Real native Electron builds and original GUI smoke tests must also pass for supported hosts.
2. **Documented scope:** Each stable CLI command must have help, safe invalid-input behavior and exit codes 0 success / 1 invalid input / 2 failed policy or Unassessed. Tests must cover input mutation, links, malformed archives and path/secret redaction.
3. **Publisher verification:** Positive validation with a legitimate, independently pinned Windows signer and Apple Developer ID / notarized macOS sample must pass on native hosts. Negative cases (unsigned, wrong signer, tampering and expired/unavailable trust chain) must fail or report Unassessed. Credentials must not enter source control or public logs.
4. **Actual installer content:** A standalone MSI/DMG/PKG recognizer is not a payload or installer-action checker. Claims about nested files must await bounded format parsers with validation fixtures. Unsupported formats are **Unassessed**.
5. **Evidence integrity:** Release-resource scans must come from the protected build job and be bound to a verified, immutable artifact digest. Never promote an imported, unattested JSON report to a trusted verdict.
6. **Distribution:** Verify package contents, install/uninstall directions, SPDX license, security reporting route, maintainer ownership and changelog. Only the maintainer should approve npm publication and GitHub Releases.

## Current validation status

| Item | Status |
| --- | --- |
| Electron static resource scan and JSON/SARIF reports | Supported within documented input bounds; continually tested |
| Offline distributable CLI installation | Automated release-candidate smoke test, not external security certification |
| Windows/macOS actual unsigned Electron build + GUI fixture | Tested in native CI, not equivalent to commercial installer release |
| Signed and notarized commercial release positive path | **Unassessed** until owned real certificates and fixtures are supplied |
| MSI/PKG installer action and payload introspection | **Unassessed**; format sniffing is not a security assessment |
| Real AI reverse-engineering resistance | **Unassessed**; synthetic Arena trials are not independent security evidence |

**No automatic v1.0.0 promotion:** do not remove caveats, mark `verified`, tag as stable or publish security claims while mandatory acceptance criteria remain incomplete. The project's original `assets/fea-icon.png` remains unchanged.
