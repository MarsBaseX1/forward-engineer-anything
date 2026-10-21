# FEA v0.4 experimental Forge patch / rollback

The new `protect preview`, `protect apply`, and `protect rollback` commands implement a narrow **JSON configuration** workflow for Forge 7.4+ (major 7). Existing `fea plan` remains review-only. Preview never writes to the project; apply uses an explicit external backup directory and refuses stale input; rollback verifies both the target and backup digests. No untrusted project code, build scripts, installers, or secrets are executed or transmitted. **ASAR is not encryption and the patch does not prove an app is secure.** See [Protect automation guide](docs/PROTECT-AUTOMATION.md).

Reproduce with `npm test && npm run protect:demo`.

# FEA v0.3.3 SARIF and Code Scanning (experimental)

`node src/cli.mjs sarif <trusted-report.json> --out <file.sarif>` produces deterministic SARIF 2.1.0 from a **complete** release-resource scan; incomplete coverage, malformed reports, duplicate findings and excessive findings fail closed. `npm run sarif:demo` compares a deliberately exposed and hardened owned fixture. The CLI never publishes raw filenames, candidate secret values, source excerpts or user-provided report messages. Results intentionally point to a tracked GitHub anchor rather than their real asset location; repository owners must keep the private scan report for triage. `docs/CODE-SCANNING.md` includes a workflow and limitations.

The separate Code Scanning workflow exercises GitHub SARIF ingestion with a clean synthetic sample. It is not a scan of arbitrary apps in the repo, not a security certification, and not a measured AI reverse-engineering defense.

# FEA v0.3.2 bounded local trial execution

`npm run arena:execute-demo` runs a locally selected and trusted Node adapter against two synthetic owned ASAR files in paired experiments. See [Arena executor](docs/ARENA-EXECUTOR.md). 33 automated tests cover the current functionality. This fixture does **not** call an AI model or measure real reverse engineering. It is not an execution sandbox, and model cost/success claims supplied by an adapter are self-reported.

# FEA v0.3.1 experimental integrations

The source-only MCP server `node src/mcp.mjs --report <trusted-report> --policy <trusted-config>` provides only sanitized audit summary, findings and policy status. There is no arbitrary file read, shell execution, target code import, HTTP listener, model call, or write tool. The spec-protocol subset supports MCP stdio initialization and `tools/list` / `tools/call`. The external model/client is managed independently: MCP running locally **does not** make a remote model private.

`npm run auth:demo` starts a **loopback-only**, transient sample API for server-side scopes, revocation, expiry and quota. Tokens can be issued only inside the reference service; no public issuance route, persistent storage, TLS, multi-process quotas or production authentication is supplied.

`arena import` converts bounded external-agent JSONL logs to the existing paired-run schema. It retains only sanitized trial fields and evidence digests. It does not run an AI Agent or verify the source, signature, factual outcomes or cost estimates of externally submitted logs. See docs/MCP.md, docs/AUTHORIZATION.md and docs/AGENT-ADAPTER.md.

# FEA v0.3 experimental Arena evaluation

The `arena compare` command consumes **existing authorized trial logs** and checks task/seed pairing, identical model/tool/environment, budget, minimum 10 valid trials, and opaque artifact digests. See [Arena protocol](docs/ARENA.md). `npm run arena:demo` only runs a deterministic fixture observer; it makes no AI/model calls and does not test real reverse-engineering resistance.

# FEA v0.2 experimental capabilities

The v0.1 resource-directory scanner remains available. v0.2 adds **bounded read-only ASAR inspection**, **review-only Electron Forge planning**, and **Windows-only Authenticode status inspection**. It does not guarantee confidentiality or tamper resistance and has not yet been independently security audited. This release does **not** apply Forge changes, create signatures, parse installers, inspect Mach-O or notarization, or run reverse-engineering benchmarks.

```sh
npm test
npm run demo && npm run demo:check
node src/cli.mjs asar-scan ./app.asar --config .fea.json --out ./audit/asar
node src/cli.mjs verify ./audit/asar/report.json --policy .fea.json
node src/cli.mjs plan ./my-electron-forge-project --out ./audit/plan
# Windows only, on a trusted host (may depend on system certificate/revocation connectivity):
node src/cli.mjs signature ./my-app.exe --thumbprint 0123456789abcdef0123456789abcdef01234567 --out ./audit/signature
```

ASAR scanning reads the archive index and bounded file contents, including referenced `.asar.unpacked` sidecars; it rejects duplicate JSON keys, links, unsafe names, invalid offsets, oversized entries, mismatched SHA-256 integrity metadata, and absent sidecars as incomplete coverage. This prototype deliberately rejects several rare or unsupported formats; test against real production Electron/asar versions before making release decisions. Malformed inputs fail closed and findings contain hashed paths only. The demo packs real `.asar` fixture archives from owned Electron source files without installing Electron; this fixture writer is for tests, not for production packaging. ASAR scanning does **not** establish whether the embedded header hash matches an external code-signed application.

The Forge planner reads only `package.json` or `forge.config.json` and emits manual configuration recommendations. It will not execute `forge.config.js` or modify build settings. The suggested ASAR integrity fuses require compatible Electron / Forge versions, verified app behavior, trusted signing and final-artifact checks. See [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses) and [ASAR integrity](https://www.electronjs.org/docs/latest/tutorial/asar-integrity).

Signature inspection uses Windows `Get-AuthenticodeSignature`. Results on non-Windows systems, errors, or missing trust data are explicitly unassessed (policy failure), not a false pass. Pin expected signers using the certificate SHA-1 thumbprint argument; signature status alone does not authenticate your intended publisher. Windows trust evaluation may consult network resources depending on OS revocation policy. Does not claim to verify all bytes or all certificate policy conditions.

## Existing v0.1 documentation

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

- v0.1 does not inspect installers `.msi`, `.dmg`, update channels, network permissions or arbitrary native binaries. v0.2 adds bounded ASAR reads and Windows-only EXE signature status, not full installer introspection. It is not a general-purpose reverse-engineering defense.
- Private paths are hashed by default, reducing report exposure but making manual localization less convenient. Findings may have false positives and false negatives.
- A `report.json` file is **not signed or authenticated**; verification is trustworthy only when that file comes from the same protected CI build context. Do not accept a third party's JSON file as proof of security.
- This experimental suite does not yet implement automatic protective code patches or a real AI-assisted reverse-engineering benchmark; Arena, MCP, and SARIF interfaces are implemented with the documented limits. The before/after report compares deterministic release-resource findings, **not attacker success rates**.
- Content checks target readable text extensions; text hidden in unknown binary formats or containers is not fully analyzed. This input limitation is not proof no secrets are present.
- Code signing, obfuscation and `asar` packing do not guarantee code confidentiality. Server-side authorization and minimizing shipped secrets are independent requirements.

See [Threat Model](docs/THREAT_MODEL.md) and [Roadmap](docs/ROADMAP.md) for the intended future protection architecture.
