# FEA runtime protection suggestions (experimental)

The `runtime` command produces reviewable suggestions for raising the cost of runtime observation and tampering. It does **not** inject code, hook processes, or claim that client-side checks are unbypassable.

## Usage

```bash
node src/cli.mjs runtime <trusted-report.json> --out <suggestions-dir>
```

Outputs `runtime.json` and `runtime.md`.

## What is suggested

- **Server-authoritative state**: when FEA006 or FEA009 findings exist, prefer short-lived server tokens and re-validation on every sensitive request.
- **Optional integrity signals**: soft ASAR integrity checks (when Fuses are enabled) and non-blocking anomaly signals. Aggressive anti-debug is discouraged.

Always test compatibility and provide a support path for legitimate debugging builds. Server-side controls remain the durable protection.
