#!/usr/bin/env node
// Trusted local observer for Arena execute.
// Reads a pre-generated FEA report or scans an owned ASAR and reports whether
// selected static findings are visible. Does NOT call AI models or external tools.
// Replace or extend this with a real REA adapter only in a controlled, authorized environment.
import fs from 'node:fs';
import {scanAsar} from '../src/asar.mjs';
import {DEFAULT_CONFIG} from '../src/core.mjs';

const request = JSON.parse(fs.readFileSync(0, 'utf8'));
if (!request || request.formatVersion !== 1 || !request.taskId || !request.artifactPath) {
  process.exit(2);
}

const taskMap = {
  'observe-source-map': 'FEA001',
  'observe-client-auth': 'FEA006',
  'observe-hardcoded-secret': 'FEA007',
  'observe-unobfuscated': 'FEA008'
};

const ruleId = taskMap[request.taskId];
if (!ruleId) process.exit(2);

let report;
try {
  report = scanAsar(request.artifactPath, DEFAULT_CONFIG);
} catch {
  process.exit(3);
}
if (!report.coverage.complete) process.exit(3);

const visible = report.findings.some(f => f.ruleId === ruleId);
process.stdout.write(JSON.stringify({
  status: visible ? 'success' : 'failure',
  costUsd: 0,
  evidenceDigest: report.inputDigest.slice(0, 16)
}));
