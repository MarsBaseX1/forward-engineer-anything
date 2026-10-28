# FEA Protect — bounded Electron Forge JSON config automation (v1.0.0 stable)

This is a reviewed config-edit workflow, **not a code protector**. ASAR packages JavaScript and resources together; it is not encryption, obfuscation, exploit mitigation or a bypass-proof license barrier. Enabling the recommended Electron Fuses raises the cost of loading unpacked or tampered resources, but does not make client code confidential.

## Explicit support matrix

- Node.js 20+ on Windows/macOS/Linux.
- Forge CLI version `7.4.x` or higher **in major 7**, as a pinned `7.x.y`, `^7.x.y`, or `~7.x.y` dependency (version string validation, **not** a proven all-minor runtime support matrix).
- Exactly one JSON configuration source: `forge.config.json` **or** `package.json#config.forge`.
- A `packagerConfig` object with `asar:false` or no `asar` property. Preexisting `asar:true` or object is treated as already configured.
- Plugins array that is plain JSON (when present). The project must already declare `@electron-forge/plugin-fuses` 7.4 or later. The tool adds or merges Forge's documented `{ name, config }` plugin object with Fuse v1 wire options `4` (`EnableEmbeddedAsarIntegrityValidation`) and `5` (`OnlyLoadAppFromAsar`) set to `true`; unrelated fuse choices are preserved.

Refuses ambiguous configurations, any `forge.config.js/.cjs/.mjs/.ts`, unsupported CLI versions, duplicate JSON keys, symlinked or hard-linked manifests, and oversized manifests. A successful edit means **JSON settings changed**, not that the app was built, works, or resists reverse engineering.

## CLI workflow

```bash
node src/cli.mjs protect preview ./project --out ./private-plan.json
node src/cli.mjs protect apply ./project --plan ./private-plan.json --state ../private-backups
node src/cli.mjs protect rollback ./project --receipt ../private-backups/fea-<uuid>/receipt.json
```

Preview produces digests, the allowed operations (asar + recommended integrity fuses), and the relative manifest name **without copying the manifest's secrets**. Apply recomputes the plan and only proceeds when before/after digests and allowed operations match. The backup directory **must be outside the project**; it stores the complete original manifest, which may contain sensitive information. Protect it with access controls and avoid uploading it as a public artifact. Keep backups until changes are fully verified.

To roll back, pass the receipt emitted by apply. Rollback refuses to overwrite a manifest that no longer has the expected post-edit SHA-256, and it verifies the backup hash before restoring byte-identical contents. Rollback does not undo a published signed build or distributed installer.

## Mandatory manual validation before shipping

1. Review the diff (`git diff`). Rebuild with the project's normal, trusted build commands and compare resource trees.
2. Run app startup, updater and feature regressions (including ASAR unpacked native modules). Confirm that the fuses do not break legitimate loading.
3. If signing is used, sign **after** rebuilding, then check the final signed files. A config-file edit does not produce a signature.
4. Rescan the **actual** resulting resources and compare findings; do not infer real security improvement from the configuration toggle alone.

This implementation assumes a trusted, quiescent local worktree; it does not safely patch adversarially concurrently modified directories or support all cross-platform filesystem edge cases. No independent audit has been conducted. Fuses require compatible Electron versions; test thoroughly.
