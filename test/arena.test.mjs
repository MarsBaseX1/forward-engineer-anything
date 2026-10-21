import test from 'node:test';
import assert from 'node:assert/strict';
import {validateSuite,validateRun,compareArena,arenaMarkdown} from '../src/arena.mjs';
const suite={formatVersion:1,suiteId:'owned-demo',authorization:'owned-or-authorized',tasks:[{id:'find-artifact'}],minTrials:10,budget:{maxDurationMs:1000,maxCostUsd:1}};
const engine={kind:'synthetic',id:'oracle',version:'1',model:'none',environment:'ci'};
const run=(variant,status='success')=>({formatVersion:1,suiteId:suite.suiteId,variant,artifactDigest:(variant==='baseline'?'a':'b').repeat(64),engine,trials:Array.from({length:10},(_,seed)=>({taskId:'find-artifact',seed,status,durationMs:0,costUsd:0}))});
test('paired evaluation derives rates and clearly labels synthetic input',()=>{
 const r=compareArena(suite,run('baseline'),run('hardened','failure'));
 assert.equal(r.tasks[0].baseline.successRate,1);assert.equal(r.tasks[0].hardened.successRate,0);
 assert.match(arenaMarkdown(r),/NOT AI resistance measurements/);
});
test('rejects missing authorization and underpowered suites',()=>{
 assert.throws(()=>validateSuite({...suite,authorization:'unspecified'}),/AUTHORIZATION/);
 assert.throws(()=>validateSuite({...suite,minTrials:1}),/MIN_TRIALS/);
});
test('rejects insufficient trials, duplicates, invalid values',()=>{
 assert.throws(()=>validateRun({...run('baseline'),trials:run('baseline').trials.slice(1)},suite,'baseline'),/NOT_ENOUGH/);
 const duplicate=run('baseline');duplicate.trials[1].seed=0;
 assert.throws(()=>validateRun(duplicate,suite,'baseline'),/DUPLICATE/);
 const negative=run('baseline');negative.trials[0].costUsd=-1;
 assert.throws(()=>validateRun(negative,suite,'baseline'),/TRIAL_INVALID/);
});
test('rejects mismatched engine, seed pairing and identical artifacts',()=>{
 const altered=run('hardened');altered.engine={...engine,model:'different'};
 assert.throws(()=>compareArena(suite,run('baseline'),altered),/ENGINE_MISMATCH/);
 const seeds=run('hardened');seeds.trials[0].seed=20;
 assert.throws(()=>compareArena(suite,run('baseline'),seeds),/UNPAIRED_SEEDS/);
 const same=run('hardened');same.artifactDigest='a'.repeat(64);
 assert.throws(()=>compareArena(suite,run('baseline'),same),/SAME_ARTIFACT/);
});
test('timeouts are budget-censored and infra failures are separate',()=>{
 const b=run('baseline','timeout');const a=run('hardened','success');
 const r=compareArena(suite,b,a);
 assert.equal(r.tasks[0].baseline.budgetCensored,10);
 assert.equal(r.tasks[0].baseline.medianSuccessfulDurationMs,null);
 assert.equal(r.tasks[0].hardened.successes,10);
});
