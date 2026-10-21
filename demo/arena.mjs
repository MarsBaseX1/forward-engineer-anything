import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {compareArena,arenaMarkdown,validateSuite} from '../src/arena.mjs';
import {writeJson} from '../src/core.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const suite=validateSuite(JSON.parse(fs.readFileSync(path.join(here,'arena-suite.json'),'utf8')));
const getReport = variant => JSON.parse(fs.readFileSync(path.join(here,'generated','reports',variant,'report.json'),'utf8'));
const engine={kind:'synthetic',id:'fixture-observer',version:'1',model:'none',environment:'node22-demo'};
const createRun=variant=>{
  const report=getReport(variant);
  if(!report.coverage.complete)throw Error('ARENA_REQUIRES_COMPLETE_AUDIT');
  const rules={'observe-source-map':'FEA001','observe-internal-config':'FEA003'};
  return {formatVersion:1,suiteId:suite.suiteId,variant,
    artifactDigest:report.inputDigest,engine,trials:suite.tasks.flatMap(t=>Array.from({length:10},(_,i)=>({
      taskId:t.id,seed:i,status:report.findings.some(f=>f.ruleId===rules[t.id])?'success':'failure',
      durationMs:0,costUsd:0
    })))};
};
const baseline=createRun('baseline'),hardened=createRun('hardened');
const output=path.join(here,'generated','reports','arena');
writeJson(path.join(output,'suite.json'),suite);
writeJson(path.join(output,'baseline.json'),baseline);
writeJson(path.join(output,'hardened.json'),hardened);
const comparison=compareArena(suite,baseline,hardened);
writeJson(path.join(output,'comparison.json'),comparison);
fs.writeFileSync(path.join(output,'comparison.md'),arenaMarkdown(comparison));
if(comparison.tasks.some(t=>t.baseline.successes!==10 || t.hardened.successes!==0))throw Error('DEMO_ORACLE_MISMATCH');
console.log('ARENA SCRIPTED FIXTURE PASS: 10 paired trials x 2 tasks (NOT an AI reverse-engineering benchmark)');
