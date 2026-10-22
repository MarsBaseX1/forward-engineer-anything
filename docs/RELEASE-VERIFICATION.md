# Verifying FEA release assets

FEA's draft-release workflow generates SHA-256 checksums and GitHub build-provenance attestations for the npm tarball, the npm pack manifest, and the checksum file. Use both checks before installing a downloaded package.

## 1. Download the assets

Download these files from the same FEA GitHub Release into one directory:

- The `@marsbasex/fea` `.tgz` package
- `npm-pack.json`
- `SHA256SUMS.txt`

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

## 3. Verify GitHub build provenance

Install a current GitHub CLI version that supports `gh attestation verify`. Then verify each attested asset:

```sh
gh attestation verify ./marsbasex-fea-1.0.0.tgz --repo MarsBaseX1/forward-engineer-anything
gh attestation verify ./npm-pack.json --repo MarsBaseX1/forward-engineer-anything
gh attestation verify ./SHA256SUMS.txt --repo MarsBaseX1/forward-engineer-anything
```

Replace the tarball filename with the exact filename you downloaded. Review the verification output and confirm that the repository is `MarsBaseX1/forward-engineer-anything` and the provenance refers to the expected release workflow and source revision. Do not accept a successful hash check as a substitute for provenance verification.

The workflow creates attestations using GitHub's `actions/attest` action. If attestations are unavailable for a particular run, do not assume the assets are attested; investigate the workflow run instead.

## Automated verification and publication gate

The `.github/workflows/fea-release-verify.yml` workflow runs on a separate GitHub-hosted runner. It downloads the actual files from the GitHub Release, verifies the exact asset set and SHA-256 checksums, cross-checks the tarball against `npm-pack.json` (including npm SHA-1/SHA-512 metadata and the complete file list), verifies each build-provenance attestation against the expected repository, signer workflow, `main` ref and source commit, then installs the downloaded tarball in a clean consumer and exercises `fea init`, `fea scan` and `fea verify`.

The draft is promoted to a public release only if all of those checks pass. If verification fails, the publish job is skipped and the release remains a draft. A manual verification run defaults to verification-only; set `publish_after_verify` to true only when deliberately publishing an already-verified draft.

## Package-content and native-signing gates

The release workflow now runs a bounded gzip/TAR content audit on the generated npm package and repeats that audit against the actual downloaded release asset on a separate read-only runner. The audit checks path safety, archive structure, the npm pack manifest and integrity metadata, required files, lifecycle scripts, runtime dependencies, executable/sensitive files, high-confidence credential patterns, and active/remote SVG content. It does not extract or execute the archive, and its heuristic checks do not prove the absence of malware or secrets.

The independent release gate also inventories optional native installer assets. Windows EXE/MSI files require a matching Authenticode signer thumbprint on a Windows runner. Apple DMG/PKG files require a matching Team ID, platform signature validation, Gatekeeper acceptance, and a stapled notarization ticket on macOS. Configure GitHub Actions secrets FEA_WINDOWS_SIGNER_THUMBPRINT and FEA_MAC_TEAM_ID before adding those asset types. The workflow verifies already-signed files; it does not sign binaries or submit them for notarization.

See [RELEASE-HARDENING.md](RELEASE-HARDENING.md) for exact scope and limitations. The current v1.0.0 release contains only the npm CLI package, so native signature/notarization checks are not applicable to its assets.

## What this proves—and what it does not

- **SHA-256 match:** the file matches the digest recorded in `SHA256SUMS.txt`.
- **Valid attestation:** GitHub can verify provenance for the exact file digest and its recorded build context.
- **Not a security certification:** neither check proves the source code is vulnerability-free, that the package contains no malware, or that Electron code cannot be reverse engineered.
- **Not commercial code signing:** these attestations do not replace Windows Authenticode signing, macOS Developer ID signing/notarization, or SmartScreen reputation.
- **Limited artifact scope:** this workflow attests the npm CLI package and its metadata. It does not claim to attest or inspect every third-party Electron installer.

If either verification fails, do not install the package. Preserve the files and workflow URL for investigation.
