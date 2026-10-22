# Arena — paired trial evaluation (v1.0.0 stable)

This is an **evaluation-log analyzer**, not an autonomous reverse-engineering agent and not a benchmark of real AI resistance. Use only with software you own or are authorized to evaluate.

Run `npm run demo && npm run demo:check && npm run arena:demo`. The demo uses a **scripted fixture observer**, 10 paired seeds for each of two tasks and zero model requests. `10/10 → 0/10` represents visibility of synthetic planted assets, **not** attack success probability or AI improvement. The two trial logs can be inspected under `demo/generated/reports/arena/`.

Use `node src/cli.mjs arena compare before.json after.json --suite suite.json --out output` to summarize externally collected trial logs. The evaluator never executes the target software or a model, invokes shell commands or makes network requests. Logs must be generated independently by an approved evaluation harness. External results are **unverified input**.

Schema: suite `{formatVersion:1,suiteId,authorization:"owned-or-authorized",tasks:[{id}],minTrials:10,budget:{maxDurationMs,maxCostUsd}}`; baseline and hardened runs `{formatVersion:1,suiteId,variant,artifactDigest:<sha256>,engine:{kind:"external"|"synthetic",id,version,model,environment},trials:[{taskId,seed,status:"success"|"failure"|"timeout"|"infrastructure-error",durationMs,costUsd}]}`. Unique `(taskId, seed)` required, each side has ≥10 valid attempts, and both sides require exactly matched seeds, engine identity and budget.

Results separate failures, budget-censored timeouts and infrastructure errors. The summary reports median success duration and median valid attempt cost; no model calls are bundled, no proof of software invulnerability is implied. No raw prompts, private keys or target file contents are emitted. Artifacts and evaluation evidence should be stored in access-controlled CI logs. For actual AI benchmarks, preserve runner version, permitted task definitions, input hashes, seed independence, wall time and usage records, and keep reserved tasks for validation.

## Executable adapter

`arena execute` runs a locally selected, operator-trusted `.mjs` adapter with explicit owned/authorized-target acknowledgment, bounded paired trials and sanitized summary output. It does not sandbox or authenticate the adapter. See [ARENA-EXECUTOR.md](ARENA-EXECUTOR.md). The bundled observation demo is synthetic and is not a real AI attack benchmark.
