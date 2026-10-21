# FEA runnable MVP — Electron resource auditing

This experimental, **dependency-free** Node.js implementation covers the requested CLI, GitHub Actions gate, before/after report and a real minimal Electron app. It is an initial implementation of the [design-stage roadmap](docs/ROADMAP.md), **not an anti-reversing product or a security certification**.

## Requirements

Node.js 20+ on Windows or macOS or Linux; no API key, model service, paid license or npm install required for scanning. Tests use Node's built-in test runner. For launching the optional demo Electron UI, install its separate `electron` dev dependency.

## Quick start

```sh
node src/cli.mjs --help
node src/cli.mjs init --profile electron-resources --out my-fea.json
node src/cli.mjs scan ./my-electron-release-resources --config my-fea.json --out ./out/baseline
node src/cli.mjs verify ./out/baseline/report.json --policy my-fea.json
```

Config is versioned **JSON** (`.fea.json`). It intentionally deviates from the proposed `fea.yml` interface to keep the first executable version dependency-free; YAML support is not claimed. `scan` produces `report.json` and `summary.txt`. Only resource **directories** from `prepackage` or `developer-extracted` stages are accepted; set `inputStage` in config. `verify` returns exit status 2 on blocking findings or incomplete coverage; 1 indicates invalid input. `scan` returns 2 if an input cannot be fully assessed. Reports contain hashed path IDs rather than raw paths or candidate key text. Save source mapping privately in your own build process; these public-facing reports intentionally omit it.

## Full reproduction: vulnerable baseline and hardened build

```sh
npm test
npm run demo
npm run demo:check
cat demo/generated/reports/comparison/comparison.md
```

`demo/electron-app/` is a **minimal, runnable Electron application** (`npm install --prefix demo/electron-app` followed by `npm start --prefix demo/electron-app`). The deterministic `demo/build.mjs` script produces both `demo/generated/baseline/app` and `demo/generated/hardened/app` from the same app source, with *only the baseline* intentionally shipping synthetic source maps, a fake PEM key marker, internal configuration, debug asset and test artifact. The hardened tree omits these accidental release assets. The demo does not need Electron installed because it tests the static release resource tree, not runtime behavior.

The baseline verify step is **expected to fail**, while hardened verification is expected to pass. `demo/check.mjs` asserts those outcomes and generates `comparison.json` and `comparison.md`. The latter contains rule-by-rule counts, resolved, introduced and remaining findings. This is a **release-hygiene** comparison only, not a quantitative proof of resistance to REA, code extraction or tampering.

## Rule coverage

| ID | Check | Notes |
| --- | --- | --- |
| FEA001 | Source map files or `sourceMappingURL` references | Can have legitimate exceptions |
| FEA002 | Text containing private-key PEM markers | Candidate marker only; no online key testing |
| FEA003 | Internal/secret-like config filenames or known internal key names | Heuristic, not exhaustive secret detection |
| FEA004 | `.pdb`, `.ilk`, `.dSYM`, `.debug` assets | Filename heuristics |
| FEA005 | Test/fixture directories and test source files | May be legitimate in some distributions |

The scanner never executes target code or checks candidate secrets online. Inputs are assumed to be from **trusted, non-concurrently modified build snapshots**. Symlinks, special files, errors, oversized inputs and time limits cause a fail-closed incomplete scan; it does not report a clean success when coverage is incomplete. Report output must live outside input directories. Rule findings are deterministic for the same input snapshot; run metadata such as time is separate. Candidate-key markers, names and contents are not included in public reports. Exceptions require a matching rule, hashed path ID, owner, reason and expiry; expired exceptions no longer suppress policy failure.

## CI

`.github/workflows/fea-security.yml` runs on pushes to main, pull requests and manual dispatch. It runs the tests, generates both demo builds, confirms baseline fails and hardened passes, creates a before/after comparison and uploads **sanitized** reports. The workflow uses read-only repository permissions. To protect a real Electron product, customize its pipeline to build a trustworthy release-resource snapshot and scan that specific directory **before packaging**. The demo workflow does not imply coverage of arbitrary software in the repository.

## Known limitations and threat boundaries

- v0.1 does **not** inspect raw `.asar`, executable `.exe`, `.msi`, `.dmg`, signing status, update channels, network permissions or binaries. It is not a general-purpose reverse-engineering defense.
- Private paths are hashed by default, reducing report exposure but making manual localization less convenient. Findings may have false positives and false negatives.
- A `report.json` file is **not signed or authenticated**; verification is trustworthy only when that file comes from the same protected CI build context. Do not accept a third party's JSON file as proof of security.
- This MVP does not yet implement the planned `protect`, `arena`, MCP interface, SARIF export or real AI-assisted reverse-engineering benchmark. The before/after report compares deterministic release-resource findings, **not attacker success rates**.
- Content checks target readable text extensions; text hidden in unknown binary formats or containers is not fully analyzed. This input limitation is not proof no secrets are present.
- Code signing, obfuscation and `asar` packing do not guarantee code confidentiality. Server-side authorization and minimizing shipped secrets are independent requirements.

See [Threat Model](docs/THREAT_MODEL.md) and [Roadmap](docs/ROADMAP.md) for the intended future protection architecture.
