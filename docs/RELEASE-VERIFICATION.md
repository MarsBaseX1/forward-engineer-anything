# Verifying FEA release assets

FEA v1.0.1 adds an archive-content audit and an SPDX 2.3 SBOM. New five-asset releases include SHA-256 checksums and GitHub build-provenance attestations for the npm tarball, npm pack manifest, SBOM, audit report, and checksum file. The already-published v1.0.0 release is a legacy three-asset release; the verifier supports both formats.

## 1. Download the assets

Download these files from the same FEA GitHub Release into one directory:

- The `@marsbasex/fea` `.tgz` package
- `npm-pack.json`
- `SHA256SUMS.txt`
- For v1.0.1 and newer SBOM-enabled releases: `sbom.spdx.json` and `package-security-audit.json`

A draft release is not a published release. These instructions apply after a maintainer has made the release assets available.

## 2. Check SHA-256 hashes

On Linux or macOS, run this in the download directory:

```sh
sha256sum -c SHA256SUMS.txt
```

On Windows PowerShell, run:

```powershell
$lines = Get-Content .\SHA256SUMS.txt
foreach ($line in $lines) {
  if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
    throw "Invalid checksum line: $line"
  }
  $expected = $Matches[1].ToLowerInvariant()
  $name = $Matches[2].Trim()
  $actual = (Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "SHA-256 mismatch: $name"
  }
  Write-Host "OK $name"
}
```

Stop if any file is missing or a hash does not match. A checksum only proves equality with the checksum file you used; it does not, by itself, prove who produced either file.

## 3. Bind the SBOM and audit report to the tarball (v1.0.1+)

Run this with Node.js in the directory containing the downloaded assets:

```sh
node --input-type=commonjs <<'NODE'
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const tarball = fs.readFileSync('marsbasex-fea-1.0.1.tgz');
const sha256 = crypto.createHash('sha256').update(tarball).digest('hex');
const sbom = JSON.parse(fs.readFileSync('sbom.spdx.json', 'utf8'));
const audit = JSON.parse(fs.readFileSync('package-security-audit.json', 'utf8'));
assert.equal(sbom.spdxVersion, 'SPDX-2.3');
assert.equal(sbom.packages[0].name, '@marsbasex/fea');
assert.equal(sbom.packages[0].versionInfo, '1.0.1');
assert.equal(sbom.packages[0].checksums[0].checksumValue, sha256);
assert.equal(audit.result, 'PASS');
assert.equal(audit.package.sha256, sha256);
console.log('SBOM and audit report match the downloaded tarball SHA-256.');
NODE
```

Stop if any assertion fails. For another version, replace the tarball filename and version value with the exact version being verified.

## 4. Verify GitHub build provenance

Install a current GitHub CLI version that supports `gh attestation verify`. Then verify each attested asset:

```sh
gh attestation verify ./marsbasex-fea-1.0.0.tgz --repo MarsBaseX1/forward-engineer-anything
gh attestation verify ./npm-pack.json --repo MarsBaseX1/forward-engineer-anything
gh attestation verify ./SHA256SUMS.txt --repo MarsBaseX1/forward-engineer-anything\n# For v1.0.1+ SBOM-enabled releases, also run:\ngh attestation verify ./sbom.spdx.json --repo MarsBaseX1/forward-engineer-anything\ngh attestation verify ./package-security-audit.json --repo MarsBaseX1/forward-engineer-anything
```

Replace the tarball filename with the exact filename you downloaded. Review the verification output and confirm that the repository is `MarsBaseX1/forward-engineer-anything` and the provenance refers to the expected release workflow and source revision. Do not accept a successful hash check as a substitute for provenance verification.

The workflow creates attestations using GitHub's `actions/attest` action. If attestations are unavailable for a particular run, do not assume the assets are attested; investigate the workflow run instead.

## 5. Automated verification and publication gate

The `.github/workflows/fea-release-verify.yml` workflow runs on a separate GitHub-hosted runner. It downloads the actual files from the GitHub Release, verifies the exact legacy three-asset or current five-asset set and SHA-256 checksums, cross-checks the tarball against `npm-pack.json` (including npm SHA-1/SHA-512 metadata and the complete file list), verifies the SBOM and audit report against the actual tarball digest when present, verifies each build-provenance attestation against the expected repository, signer workflow, `main` ref and source commit, then installs the downloaded tarball in a clean consumer and exercises `fea init`, `fea scan` and `fea verify`.

The draft is promoted to a public release only if all of those checks pass. If verification fails, the publish job is skipped and the release remains a draft. A manual verification run defaults to verification-only; set `publish_after_verify` to true only when deliberately publishing an already-verified draft.

## What this proves—and what it does not

- **SHA-256 match:** the file matches the digest recorded in `SHA256SUMS.txt`.
- **Valid attestation:** GitHub can verify provenance for the exact file digest and its recorded build context.
- **Not a security certification:** neither check proves the source code is vulnerability-free, that the package contains no malware, or that Electron code cannot be reverse engineered.
- **Not commercial code signing:** these attestations do not replace Windows Authenticode signing, macOS Developer ID signing/notarization, or SmartScreen reputation.
- **Limited artifact scope:** this workflow attests the npm CLI package and its metadata. It does not claim to attest or inspect every third-party Electron installer.

If either verification fails, do not install the package. Preserve the files and workflow URL for investigation.
