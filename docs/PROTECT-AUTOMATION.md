# FEA v0.4 — bounded Electron Forge JSON config patch (experimental)

This is a reviewed config-edit workflow, **not a code protector**. ASAR packages JavaScript and resources together; it is not encryption, obfuscation, exploit mitigation or a bypass-proof license barrier.

## Explicit support matrix

- Node.js 20+ on Windows/macOS/Linux. Tested in CI on Windows and Ubuntu; no Mac runner yet.
- Forge CLI version `7.4.x` or higher **in major 7**, as a pinned `7.x.y`, `^7.x.y`, or `~7.x.y` dependency (version string validation, **not** a proven all-minor runtime support matrix).
- Exactly one JSON configuration source: `forge.config.json` **or** `package.json#config.forge`.
- A `packagerConfig` object with `asar:false` or no `asar` property. Preexisting `asar:true` or object is treated as an already configured no-op.
- Only the `asar:true` setting is edited. No auto-Fuse changes, plugins, dependency updates, removal of source maps, integrity attestation, or signed artifact edits.

Refuses ambiguous configurations, any `forge.config.js/.cjs/.mjs/.ts`, unsupported CLI versions, duplicate JSON keys, symlinked or hard-linked manifests, and oversized manifests. A successful edit means **a JSON setting changed**, not that the app was built, works, or resists reverse engineering.

## CLI workflow

```bash
node src/cli.mjs protect preview ./project --out ./private-plan.json
node src/cli.mjs protect apply ./project --plan ./private-plan.json --state ../private-backups
node src/cli.mjs protect rollback ./project --receipt ../private-backups/fea-<uuid>/receipt.json
```

Preview produces digests, the allowed operation, and the relative manifest name **without copying the manifest's secrets**. Apply recomputes the plan and only proceeds when before/after digests and allowed operations match. The backup directory **must be outside the project**; it stores the complete original manifest, which may contain sensitive information. Protect it with access controls and avoid uploading it as a public artifact. Keep backups until changes are fully verified.

To roll back, pass the receipt emitted by apply. Rollback refuses to overwrite a manifest that no longer has the expected post-edit SHA-256, and it verifies the backup hash before restoring byte-identical contents. Rollback does not undo a published signed build or distributed installer.

## Mandatory manual validation before shipping

1. Review the diff (`git diff`). Rebuild with the project's normal, trusted build commands and compare resource trees.
2. Run app startup, updater and feature regressions (including ASAR unpacked native modules).
3. If signing is used, sign **after** rebuilding, then check the final signed files. A config-file edit does not produce a signature.
4. Rescan the **actual** resulting resources and compare findings; do not infer real security improvement from the configuration toggle alone.

This first implementation assumes a trusted, quiescent local worktree; it does not safely patch adversarially concurrently modified directories or support all cross-platform filesystem edge cases. No independent audit has been conducted.
