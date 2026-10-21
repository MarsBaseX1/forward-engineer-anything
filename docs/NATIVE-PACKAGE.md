# FEA v0.4.2 — native Electron Forge package evidence (experimental)

This test is intentionally restricted to the **owned, minimal** `demo/real-electron-app` fixture. Unlike the earlier synthetic EXE header and VM startup contract, its [native CI](../.github/workflows/fea-native-package.yml) installs actual Electron 33.4.11, Forge 7.4.0, plugin-fuses 7.4.0 and @electron/fuses 1.8.0, then invokes `electron-forge package --arch=x64` on **Windows** and **macOS Intel**. It does not build or run arbitrary third-party code.

Run on a native Windows or Intel Mac development host (Node.js 22, network access, graphical session):

```sh
npm test
npm install --prefix demo/real-electron-app --no-audit --no-fund
npm run package --prefix demo/real-electron-app -- --arch=x64
npm run native:verify
```

### Verification evidence

The verifier fails unless all checked properties pass:

1. It discovers exactly one expected `FEAElectronSmoke` packaged executable and `app.asar` within Forge's native output directory.
2. It reads the **actual Electron binary Fuse V1 wire** via the upstream `@electron/fuses` API, and requires RunAsNode, NODE_OPTIONS, and CLI inspect disabled, plus ASAR integrity validation and ASAR-only loading enabled. The macOS fuse wire is in Electron Framework inside `.app`, not the thin Mach-O launcher.
3. It hashes the exact JSON ASAR header string read by `@electron/asar.getRawHeader`; checks against the Windows `INTEGRITY/ELECTRONASAR` PE resource or macOS `ElectronAsarIntegrity['Resources/app.asar']` entry in Info.plist.
4. It launches the packaged GUI executable and waits for a DOM marker from a real BrowserWindow `did-finish-load` event. The owned app exits 0 on success and writes an exclusive result file. Missing marker, process failure or timeout is a failure.

The evidence JSON omits raw paths, source code and secret values. It lives at `demo/generated/reports/real-electron/<platform>/real-package.json`. The native runner uploads only these small sanitized results, **not** 100+ MB executable bundles. The artifact is a CI fixture, not a distributed production binary.

### Limits and risk boundaries

- Neither Windows Authenticode nor Apple Developer ID signature, notarization, Gatekeeper and SmartScreen reputation are verified. An unsigned GUI can run on the CI host without being a distributable you should ship to customers.
- The integrity header check compares two values *inside the same package*; its independent authenticity requires a trustworthy signed release chain. Successful comparison does not prevent a sufficiently privileged attacker from patching unsigned binaries and recomputing checksums.
- The sample does not exercise complete installer formats, automatic updates, malicious input handling, real end-user desktop interactions, GPU performance or Electron app lifecycle corner cases.
- Actual native execution is performed on GitHub runners, not claimed from Linux-only local unit tests. Windows/macOS must both report success in Actions before considering the integration verified.
- `@electron/fuses` and ASAR parser are trusted upstream packages loaded **only from pinned fixture dependencies**. Never point this workflow at a stranger's executable Forge config, or call it an arbitrary binary sandbox.

Sources: [Electron Forge Fuses](https://www.electronforge.io/config/plugins/fuses), [ASAR integrity](https://www.electronjs.org/docs/latest/tutorial/asar-integrity), [Electron Fuses](https://github.com/electron/fuses).
