# FEA v0.4.3 — Release provenance & publisher verification (experimental)

This stage adds **read-only** release snapshot evidence and native OS publisher verification. The result is not a signing service, notarization submission tool, antivirus scanner, or installer parser.

## Artifact snapshot / independent digest pin

```bash
node src/cli.mjs release manifest ./out/MyProduct.exe --out ./.fea/manifest.json
node src/cli.mjs release manifest ./out/MyProduct.exe --expected-sha256 <previously-trusted-manifest-snapshot-sha256> --out ./.fea/recheck.json
```

For an `.app` directory, the tool traverses files (up to 20,000 files / 2GB total / 600 MB per file), rejects symlinks, hardlinks, unsafe nodes, and concurrently altered file sizes/mtime, hashes bytes, and emits only hashed path identifiers. **Real macOS bundles often contain legitimate framework symlinks; those are intentionally unsupported in this version and will fail closed.** Directory snapshots are not a substitute for Apple code-signature verification.

Digest matching is useful **only when the expected digest comes from a separately trusted location** (protected release process, signed metadata, etc.). An unsigned JSON file stored next to an altered package is not an authenticity check. MSI, DMG, PKG and ZIP can be hashed as opaque files, but their interior files are **not examined** and no installability or trust claim is made.

## Windows: signature status and exact signer pin

Run **on Windows**, after signing the release EXE:

```powershell
node src/cli.mjs release publisher .\dist\MyProduct.exe --platform win32 --thumbprint <SHA1_CERT_THUMBPRINT_40_HEX> --out .\.fea\windows-publisher.json
```

Uses `Get-AuthenticodeSignature -LiteralPath` through `powershell.exe`, sends the filename via JSON stdin, and never builds a script from a user-supplied path. Requires OS status `Valid` AND exact pinned signer certificate thumbprint; otherwise exits nonzero (`2`). A missing pin or running on another OS is `unassessed`, not success. Certificate thumbprints identify a particular signing certificate and change on certificate renewal. A valid signature is *not* evidence of SmartScreen reputation or immunity from code modification.

## macOS: signed app + publisher Team ID + notarization evidence

Run **on macOS** with a signed and notarized `.app` bundle:

```bash
node src/cli.mjs release publisher ./dist/MyProduct.app --platform darwin --team-id ABC1234XYZ --out ./.fea/mac-publisher.json
```

Requires `codesign --verify --deep --strict`, `codesign --display --verbose=4` with an exact expected TeamIdentifier, `spctl --assess --type execute`, and `xcrun stapler validate`. All must succeed; if system commands are unavailable, results are `unassessed`. A stapled ticket is required by this prototype's policy. Apps notarized solely via an online ticket without stapling are not accepted by this command, even if Gatekeeper would normally accept them. The tool **does not submit to Apple** or create a certificate.

## CI and testing boundaries

The `fea-release-trust.yml` matrix runs on Ubuntu, Windows and macOS Intel, with **negative tests using an unsigned fake EXE**. It proves the tool fails closed for the fixture. Because the project does not store certificate/private-key credentials, CI cannot prove verification of a genuine Developer ID or OV/EV signed release. Actual positive signing-chain validation must be separately performed in an authorized publisher CI, and then the exact identity and final bytes pinned.

The public reports intentionally contain only status, rule IDs, hashes, file sizes, and booleans; they do not embed absolute paths, signing credentials, or certificate private keys. Configure access restrictions for internal CI evidence. The original `assets/fea-icon.png` is untouched.

References: [Windows Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature), [Apple notarization process](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
