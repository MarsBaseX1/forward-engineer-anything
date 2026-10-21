import test from 'node:test';
import assert from 'node:assert/strict';
import {importExternalTrials} from '../src/arena-import.mjs';
import {compareArena} from '../src/arena.mjs';
const suite={formatVersion:1,suiteId:'owned-unaudited',authorization:'owned-or-authorized',tasks:[{id:'recover-known-string'}],minTrials:10,budget:{maxDurationMs:1000,maxCostUsd:1}};
const desc=(variant)=>({variant,artifactDigest:(variant==='baseline'?'a':'b').repeat(64),engine:{kind:'external',id:'own-agent',version:'v1',model:'model-v1',environment:'win-vm-v1'}});
const jsonl=(status)=>Array.from({length:10},(_,seed)=>JSON.stringify({taskId:'recover-known-string',seed,status,durationMs:50,costUsd:.01,evidenceSha256:'c'.repeat(64),trace:'PRIVATE_TRACE',absolutePath:'C:\\source'})).join('\n');
test('import external run logs strips private fields and requires evidence fingerprints',()=>{
 const before=importExternalTrials(suite,desc('baseline'),jsonl('success'));
 const after=importExternalTrials(suite,desc('hardened'),jsonl('timeout'));
 assert.equal(before.provenance.source,'external-self-reported');
 assert.equal(before.provenance.evidenceValidated,false);
 assert.equal(JSON.stringify(before).includes('PRIVATE_TRACE'),false);
 assert.equal(compareArena(suite,before,after).tasks[0].baseline.successes,10);
 assert.match(compareArena(suite,before,after).notice,/unverified/i);
});
test('reject malformed and unpaired external evidence',()=>{
 assert.throws(()=>importExternalTrials(suite,desc('baseline'),jsonl('success').replace(/"evidenceSha256":"c{64}"/,'"evidenceSha256":"invalid"')),/ARENA_EXTERNAL_EVIDENCE_DIGEST_REQUIRED/);
 assert.throws(()=>importExternalTrials(suite,desc('baseline'),jsonl('success').split('\n').slice(0,9).join('\n')),/ARENA_NOT_ENOUGH_VALID_TRIALS/);
 assert.throws(()=>importExternalTrials(suite,{...desc('baseline'),engine:{...desc('baseline').engine,kind:'synthetic'}},jsonl('success')),/ARENA_EXTERNAL_DESCRIPTOR_INVALID/);
});
