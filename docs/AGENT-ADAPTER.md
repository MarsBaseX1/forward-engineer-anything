# Arena external-agent log adapter (v1.0.0 stable)

FEA deliberately does not install or automatically execute REA or other agents. For real evaluations, you operate the chosen agent **outside FEA**, with permission on **your own or explicitly authorized test binary**, fixed tool/model versions, recorded environment, validated task success criteria and a capped runtime/cost budget.

The bridge is a newline-delimited JSON (JSONL) file, one trial per line:

```json
{"taskId":"observe-source-map","seed":0,"status":"success","durationMs":1320,"costUsd":0.01,"evidenceSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

Allowed statuses: `success`, `failure`, `timeout`, `infrastructure-error`. `evidenceSha256` should be the SHA-256 digest of **restricted** evidence held outside the public report. FEA checks the digest's syntax; it **does not read, validate or certify the evidence**, and JSONL fields remain self-reported.

Descriptor (`descriptor.json`) includes `variant` (`baseline` / `hardened`), the 64-hex artifact digest and `engine`:

```json
{"variant":"baseline","artifactDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","engine":{"kind":"external","id":"authorized-agent","version":"pinned-version","model":"pinned-model","environment":"pinned-env"}}
```

Run the same declared suite against baseline and hardened artifacts with **at least 10 valid paired seeds per task**. Preserve full raw agent traces only in restricted storage. Then:

```bash
node src/cli.mjs arena import baseline.jsonl --suite demo/arena-suite.json --descriptor baseline-descriptor.json --out baseline-run.json
node src/cli.mjs arena import hardened.jsonl --suite demo/arena-suite.json --descriptor hardened-descriptor.json --out hardened-run.json
node src/cli.mjs arena compare baseline-run.json hardened-run.json --suite demo/arena-suite.json --out ./arena-results
```

For a no-network, no-agent validation of the adapter itself, run `npm run arena:import-demo`. These demo statistics are **not actual AI reverse-engineering results**. Never present fixture outcomes or unverified self-reported logs as independent measurements of application security.
