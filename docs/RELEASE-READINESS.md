# FEA v0.4.1 — Release readiness (experimental)

This phase adds **version-declaration compatibility checks** and **read-only inspection of a developer-provided unpacked Electron build**. It does **not** build Electron, execute untrusted projects, flip or read embedded binary fuse bits, verify macOS notarization, validate an installer, or prove reverse-engineering resistance.

## 1. Version compatibility (static declarations only)

```bash
node src/cli.mjs release compat ./trusted-electron-project --platform win32 --out ./reports/compat.json
node src/cli.mjs release compat ./trusted-electron-project --platform darwin --out ./reports/mac-compat.json
```

The check uses **exactly pinned** `electron` and `@electron-forge/cli` values in `package.json`; `^`, `~`, wildcard and dynamic JavaScript Forge configurations are marked *unassessed*, not assumed safe. JSON Forge config must explicitly enable `packagerConfig.asar`.

Official Electron platform support for embedded ASAR integrity: **macOS Electron >=16** and **Windows Electron >=30**. Automated header-hash packaging with Electron Forge requires **Forge >=7.4.0**. Compatibility means only that declared versions satisfy prerequisites; **it does not establish the installed Electron version, fuse plugin configuration, actual fuse bits, or linked integrity metadata**. See the [Electron ASAR integrity documentation](https://www.electronjs.org/docs/latest/tutorial/asar-integrity).

## 2. Inspect an existing unpacked release

```bash
# Windows unpacked layout: <root>/*.exe and <root>/resources/app.asar
node src/cli.mjs release inspect ./out/my-app-win32-x64 --platform win32 --config .fea.json --out ./reports/release \
  --asar-sha256 <trusted-precomputed-sha256>

# macOS bundle: My.app/Contents/MacOS/<executable> and Contents/Resources/app.asar
node src/cli.mjs release inspect ./out/My.app --platform darwin --config .fea.json --out ./reports/mac-release
```

The inspector reads a regular PE or Mach-O *header*, hashes the binary and ASAR, scans ASAR contents using the existing FEA rule engine, and evaluates the existing policy. A pinned expected SHA-256 is optional but recommended; pin it in an independently trusted build context. It rejects symlinked artifact entries, ambiguous executable counts, malicious archive structure, blocked findings, mismatched pinned digests and output directories inside the release root.

`release.json` and `asar-report.json` record sanitized results. A successful exit means **only the static checks performed passed**. It is not an assertion that the binary is executable, authentic, signed, hardened, bug-free, or contains verified fuse settings. The input must be a trusted, stable, unpacked snapshot; parsing is not a substitute for package/build provenance.

## 3. Startup regression contract (synthetic mock)

```bash
npm run demo
npm run release:demo
npm test
```

`release:demo` verifies declared prerequisites, a synthetic unpacked PE/ASAR fixture, and the *owned demo's* Electron main-process startup contract in an isolated `vm` with a fake Electron API. The test checks that a window is created with sandboxing, context isolation and Node integration disabled. **No GUI or actual packaged Electron executable is launched.** Do not run this VM-based fixture helper on untrusted third-party code.

## Remaining work before production claims

Actual Electron Forge packaging and signed binary checks on native hosts; independently verifying embedded ASAR header hashes and fuse bits; real GUI smoke tests in platform-specific CI; signer and notarization verification; installer format handling; protecting against concurrently mutating build inputs. Failures and `unassessed` checks must not be presented as evidence of resistance to reverse engineering.
