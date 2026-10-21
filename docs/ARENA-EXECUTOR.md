# FEA v0.3.2 Arena executor — experimental

This runner accepts **only a locally selected, operator-trusted Node.js `.mjs` adapter**. It does **not** download models, inspect third-party software, sandbox code, or independently verify model answers. The operator must own the artifacts or have explicit authorization. Never run adapters from untrusted sources.

## Reproduce the synthetic trial demonstration

```sh
npm test
npm run demo
npm run arena:execute-demo
cat demo/generated/reports/arena-execution/comparison.md
```

The sample `demo/trusted-observer.mjs` observes FEA001 and FEA003 static findings in intentionally altered **owned** ASAR fixtures. It never invokes an AI model; its high baseline visibility rates are **not AI reverse-engineering success rates**.

## Anti-REA suite (new rules)

A second suite covers the rules added for raising REA-style analysis cost:

```sh
node src/cli.mjs arena execute \
  --suite demo/arena-suite-anti-rea.json \
  --baseline demo/generated/baseline/app.asar \
  --hardened demo/generated/hardened/app.asar \
  --adapter demo/rea-observer.mjs \
  --engine demo/arena-executor-engine.json \
  --out demo/generated/reports/arena-anti-rea \
  --i-own-artifacts
```

See [REA-ADAPTER.md](REA-ADAPTER.md) for task IDs and how to replace the observer with a real REA adapter.

## Contract

CLI: `node src/cli.mjs arena execute --suite <suite.json> --baseline <owned-artifact> --hardened <owned-artifact> --adapter <trusted.mjs> --engine <engine.json> --out <output-directory> --i-own-artifacts`.

The runner sends one JSON line to adapter standard input with `{formatVersion:1,variant,taskId,seed,artifactPath,budget}`. The adapter must respond with a single JSON object `{status:"success"|"failure"|"timeout",costUsd:<nonnegative number>}` on stdout and exit zero. Requests are paired by task/seed, with alternating variant order. Each trial has a wall-clock timeout, capped captured output, no inherited environment variables, and the adapter runs with `shell:false`. These controls **do not provide an OS or network sandbox**, and they **do not enforce remote token or API spend**. Only run reviewed adapters in a separate trusted evaluation machine or container with appropriate resource limits.

Requires at least 10 valid trials per task/variant; max 400 scheduled trials total, max 60 seconds per trial, max 100MB input artifact. The runner rejects symlink artifact/adapter inputs, same-content baseline and hardened artifacts, invalid engine descriptors and missing explicit acknowledgment.

The final report records pinned engine descriptors, task/seed pairs, per-trial durations, reported costs, outcome and SHA-256 fingerprints; it intentionally does not publish prompts, raw model responses, local paths or credentials. The report does not authenticate adapter-reported outcomes or prove all input artifacts were isolated from mutation during a run. Failed adapters are recorded as infrastructure errors and cannot create a positive security result; not enough valid trials fails validation.

External model providers can be integrated only through a separately approved adapter/runner that supplies access without embedding live secrets into FEA outputs; keep original evidence in restricted storage, verify results and billing, and record model/tool versions and trial success rubric. Do not publish vendor API keys or private transcripts.
