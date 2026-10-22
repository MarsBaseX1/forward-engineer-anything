# FEA MCP read-only server (v1.0.0 stable)

This is a limited MCP stdio transport for **precomputed FEA reports**. Based on the MCP 2025-11-25 basic initialization and tool protocol; optionally negotiates 2025-06-18. Uses newline-delimited JSON-RPC on stdin/stdout and no npm dependencies. This is not a full MCP SDK implementation (no resources, sampling, tasks or HTTP transport).

## Run

```bash
npm run demo && npm run demo:check
node src/mcp.mjs --report demo/generated/reports/hardened/report.json --policy .fea.json
```

Configure your own MCP-compatible client to launch that command. Files are chosen at process startup by a trusted local operator; **no MCP tool may select paths**, run targets, update configurations, upload data or issue shell commands.

Available tools: `fea_report_summary` (coverage / rule totals), `fea_list_findings` (hashed path IDs and rule IDs, optional ruleId and capped limit), `fea_policy_check` (same `verifyReport` engine used by the CLI). The report parser rejects symlinks, oversized reports and unsupported shapes. Outputs are strictly whitelisted and never include raw evidence text, real file names, keys or candidate secrets.

Security assumptions: trusted report and config, no concurrent mutation while MCP is running. An attacker-controlled report is not a security attestation. MCP tool output is still visible to the connected client/model; use your provider's privacy controls. Only connect trusted local clients and avoid sharing sensitive CI reports.

Run `npm run mcp:demo` and `npm test` for protocol and no-path-access tests. The server does not provide external agent execution or automatic AI benchmark runs.
