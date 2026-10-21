// Demo-only trusted adapter: executes as a child process and inspects OWNED ASAR fixtures.
// It does NOT run an AI model. Never label these results as reverse-engineering success rates.
import {scanAsar} from '../src/asar.mjs';
import {DEFAULT_CONFIG} from '../src/core.mjs';
import fs from 'node:fs';
const request=JSON.parse(fs.readFileSync(0,'utf8'));
if(!request||request.formatVersion!==1||!['observe-source-map','observe-internal-config'].includes(request.taskId))process.exit(2);
const report=scanAsar(request.artifactPath,DEFAULT_CONFIG);
if(!report.coverage.complete)process.exit(3);
const id={'observe-source-map':'FEA001','observe-internal-config':'FEA003'}[request.taskId];
process.stdout.write(JSON.stringify({status:report.findings.some(x=>x.ruleId===id)?'success':'failure',costUsd:0}));
