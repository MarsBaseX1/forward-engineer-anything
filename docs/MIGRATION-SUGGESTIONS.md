# FEA migration suggestions (v1.0.0 stable)

When a trusted scan report contains **FEA006** (client-side authorization/license judgment) or **FEA007** (hardcoded secret candidates), the `migrate` command produces reviewable architectural suggestions.

These suggestions do **not** rewrite code, do not execute the target project, and do not claim that following them makes software immune to reverse engineering. They raise the cost of unauthorized use and secret extraction by moving authoritative decisions and secrets off the client.

## Usage

```bash
node src/cli.mjs scan ./my-electron-resources --config .fea.json --out ./audit
node src/cli.mjs migrate ./audit/report.json --out ./audit/migrate
```

Outputs:

- `suggestions.json` — structured recommendations
- `suggestions.md` — human-readable steps and before/after examples

## What is suggested

| Finding | Recommendation |
|---------|----------------|
| FEA006 | Move entitlement and license decisions to the server; treat remaining client checks as cosmetic. |
| FEA007 | Rotate exposed credentials; proxy third-party calls; issue short-lived server tokens. |

Always review the diff, run functional tests, and rescan the final release resources after changes.
