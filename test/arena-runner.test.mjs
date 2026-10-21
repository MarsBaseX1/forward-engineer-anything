import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {runPairedArena} from '../src/arena-runner.mjs';

function fixture(t, adapterSource = `
import fs from 'node:fs';
const req=JSON.parse(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify({status:req.variant==='baseline'?'success':'failure',costUsd:0}));
`) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'fea-execute-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const write=(name,content)=>{const f=path.join(dir,name);fs.writeFileSync(f,content);return f;};
  const args={
    suite:{formatVersion:1,suiteId:'owned-fixture',authorization:'owned-or-authorized',tasks:[{id:'analyze-source'}],minTrials:10,budget:{maxDurationMs:3000,maxCostUsd:0.1}},
    baselineFile:write('baseline.asar','baseline'),hardenedFile:write('hardened.asar','hardened'),
    adapterFile:write('trusted.mjs',adapterSource),
    engine:{kind:'synthetic',id:'fixture-observer',version:'0.3.2',model:'none',environment:'node22'},
    acknowledgeExecution:true
  };
  return {dir,args,write};
}
test('bounded runner executes ten paired trials on owned artifacts, retaining no raw outputs',t=>{
  const {args}=fixture(t);
  const result=runPairedArena(args);
  assert.equal(result.baseline.trials.length,10);
  assert.equal(result.hardened.trials.length,10);
  assert.equal(result.comparison.tasks[0].baseline.successRate,1);
  assert.equal(result.comparison.tasks[0].hardened.successRate,0);
  assert.equal(result.comparison.provenance.evidenceValidated,false);
  assert.equal(result.comparison.provenance.remoteSpendEnforced,false);
  assert.match(result.comparison.notice,/self-reported/);
  assert.equal(Object.hasOwn(result.baseline.trials[0],'rawOutput'),false);
  assert.match(result.baseline.trials[0].evidenceSha256,/^[0-9a-f]{64}$/);
});
test('explicit execution acknowledgment and trustworthy script are required',t=>{
  const {args,write}=fixture(t);
  assert.throws(()=>runPairedArena({...args,acknowledgeExecution:false}),/ACK_REQUIRED/);
  assert.throws(()=>runPairedArena({...args,adapterFile:write('adapter.txt','hello')}),/NODE_ADAPTER_REQUIRED/);
  assert.throws(()=>runPairedArena({...args,baselineFile:args.hardenedFile}),/SAME_ARTIFACT/);
});
test('oversized scheduling and invalid engine fail before adapter execution',t=>{
  const {args}=fixture(t);
  const huge={...args.suite,minTrials:210};
  assert.throws(()=>runPairedArena({...args,suite:huge}),/TRIAL_LIMIT/);
  assert.throws(()=>runPairedArena({...args,engine:{...args.engine,kind:'unknown'}}),/ENGINE_DESCRIPTOR/);
});
test('adapter failures do not count as successful protection',t=>{
  const {args}=fixture(t,`process.exitCode=2;`);
  assert.throws(()=>runPairedArena(args),/ARENA_NOT_ENOUGH_VALID_TRIALS/);
});
test('child adapter receives no inherited secret environment variables',t=>{
  const {args}=fixture(t,`
import fs from 'node:fs';
fs.readFileSync(0,'utf8');
process.stdout.write(JSON.stringify({status:process.env.FEA_RUNNER_PRIVATE_TOKEN?'success':'failure',costUsd:0}));`);
  process.env.FEA_RUNNER_PRIVATE_TOKEN='synthetic-token-not-for-child';
  try {
    const result=runPairedArena(args);
    assert.equal(result.comparison.tasks[0].baseline.successRate,0);
  } finally {delete process.env.FEA_RUNNER_PRIVATE_TOKEN;}
});
