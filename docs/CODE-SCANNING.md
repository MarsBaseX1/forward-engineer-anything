# FEA SARIF / GitHub Code Scanning integration (v1.0.0 stable)

## Supported workflow

FEA scans *trusted Electron release-resource directories or bounded ASAR inputs*. `fea sarif` converts a **complete**, already-produced JSON scan report to SARIF 2.1.0. Reports containing incomplete coverage, unknown rules, malformed findings, duplicate rule/path pairs or excessive result counts are refused.

The SARIF output contains only catalog-generated rule titles, normalized severity, hashed path IDs, stable fingerprints, input-stage labels, input digests and a **single repository-tracked anchor URI** `.github/fea-sarif-anchor.md` at line 1 for each result. This is **not** the actual resource location and must not be interpreted as source annotation. FEA does not know repository-relative source paths from its sanitized reports; creating convincing real paths here would leak data or misrepresent the affected file.

## Reproduce locally

```bash
npm test
npm run demo && npm run demo:check && npm run sarif:demo
node src/cli.mjs sarif demo/generated/reports/baseline/report.json --out demo/generated/reports/baseline/findings.sarif
```

The intentionally exposed baseline creates six **synthetic** findings, whereas the hardened fixture creates zero. Neither is a real security benchmark. Do not publish intentional synthetic findings to your production Code Scanning dashboard.

## GitHub integration

The checked-in `.github/workflows/fea-code-scanning.yml` runs on pushes to `main` or manual dispatch. It audits the **clean owned synthetic demo** and calls `github/codeql-action/upload-sarif@v4` with `security-events: write` and `contents: read`. The workflow confirms API ingestion plumbing only. It does **not** scan arbitrary users' applications or their final EXE/MSI/DMG.

To adopt for your own app, update the workflow's build step to produce your own **trusted build snapshot** and point `scan` to it. Run `verify` for a separate fail-closed release policy, and run `sarif` on completed scans. Ensure `.github/fea-sarif-anchor.md` exists on the target branch. Protect the CI environment and scanning report storage. When scanning fails or is incomplete, fail the workflow; do not emit a zero-alert SARIF as a fallback. Scan and upload steps can be separated so valid findings still reach Code Scanning when policy blocks a release.

For a release CI script, use these commands after the trusted build has finished:

```bash
node src/cli.mjs scan ./trusted-release-resources --config .fea.json --out ./.fea/reports/release
node src/cli.mjs sarif ./.fea/reports/release/report.json --out ./.fea/reports/release/findings.sarif
node src/cli.mjs verify ./.fea/reports/release/report.json --policy .fea.json
```

Policy failures are expected for detected findings. In GitHub Actions, use a separate upload step with `if: always()` but only when SARIF file creation was successful, not on partial/failed scans. Never accept a SARIF or JSON report supplied by an untrusted fork as verification of a release. Uploading on pull requests from forks needs separate permission consideration; the included workflow intentionally avoids fork PR writes.

GitHub docs: [Uploading SARIF](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github) and [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Limitations and risk

- The privacy anchor produces **repository-visible alerts without source-file navigation**; triage requires privately mapping a finding's hashed ID to the build resource.
- Hash IDs for predictable filenames are not strong secrecy. Reports still deserve restricted access; no raw filenames or secret contents are added to public SARIF.
- Same fixed anchor is used for all findings; fingerprints help group recurring issues, but real-world alert grouping must be checked in GitHub after each supported tooling upgrade.
- Even a perfectly clean complete resource scan does not prove code cannot be read, modified, copied, or reimplemented.
- Public GitHub.com repositories support Code Scanning; private repository support depends on the plan and whether Code Security is enabled.
