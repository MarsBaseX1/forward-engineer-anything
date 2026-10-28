# FEA — Production acceptance criteria (v1.0.1)

FEA v1.0.1 is a stable dependency-free Node.js CLI for Electron release-resource inspection, policy gating, and controlled hardening. No single security tool can prevent all reverse engineering. Treat production use as a reproducible release decision with documented boundaries.

## Install / uninstall

Requirements: Node.js >=20 and npm.

```sh
npm test
npm run distribution:smoke
```

The offline smoke test runs `npm pack`, installs the tarball into a temporary directory without network access, and executes basic CLI commands. It does **not** publish to npm or validate publisher signatures.

## Release criteria

All criteria below must be explicitly satisfied before relying on FEA for a production release decision:

1. **Cross-platform CI:** Windows/macOS/Linux unit and offline install smoke tests must pass.
2. **Documented scope:** Each stable CLI command must have help, safe invalid-input behavior and exit codes 0 success / 1 invalid input / 2 failed policy or Unassessed.
3. **Publisher verification:** Positive validation with a legitimate, independently pinned Windows signer and Apple Developer ID / notarized macOS sample must pass on native hosts. Negative cases must fail or report Unassessed.
4. **Actual installer content:** Unsupported formats are **Unassessed**.
5. **Evidence integrity:** Release-resource scans must come from the protected build job and be bound to a verified, immutable artifact digest.

## Current validation status (v1.0.1)

| Item | Status |
| --- | --- |
| Electron static resource scan (FEA001–FEA009) and JSON/SARIF | Supported within documented bounds |
| Offline distributable CLI installation | Automated smoke test |
| Forge JSON automation (protect) | Supported for compatible JSON configs |
| Suggestion generators (migrate / obfuscate / runtime) | Supported |
| Arena protocol + local trusted adapter | Supported (synthetic fixtures) |
| Windows/macOS unsigned Electron build + GUI fixture | Tested in native CI |
| Signed / notarized commercial release positive path | **Unassessed** without real certificates |
| MSI/PKG installer payload introspection | **Unassessed** |
| Real AI reverse-engineering resistance | **Unassessed** |

## Honest boundaries

- Does not claim software is un-reverse-engineerable.
- Installer content parsing and real commercial certificate positive verification remain limited.
- Arena results do not prove reverse-engineering resistance.
- No independent security audit or certification is claimed.

See [CHANGELOG.md](../CHANGELOG.md) and [ANTI-REA-HARDENING.md](ANTI-REA-HARDENING.md).
