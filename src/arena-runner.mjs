import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {validateSuite,compareArena,validateRun} from './arena.mjs';

// The runner only executes an operator-selected, trusted Node .mjs adapter.
// It is NOT a sandbox and it does not execute software under examination.
// No prompts, agent outputs, source paths, or credentials appear in public reports.
const sha = data => crypto.createHash('sha256').update(data).digest('hex');
const MAX_TRIALS=400, MAX_ARTIFACT_BYTES=100_000_000;
function checkedFile(filename,limit) {
  if(typeof filename!=='string'||!filename)throw Error('ARENA_FILE_REQUIRED');
  const stat=fs.lstatSync(filename);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>limit)throw Error('ARENA_UNSUPPORTED_FILE');
  const resolved=fs.realpathSync(filename);
  if(!fs.statSync(resolved).isFile())throw Error('ARENA_UNSUPPORTED_FILE');
  return resolved;
}
function safeEngine(engine){
  if(!engine || !['synthetic','external'].includes(engine.kind) ||
    !['id','version','model','environment'].every(k=>typeof engine[k]==='string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/.test(engine[k])))
    throw Error('ARENA_ENGINE_DESCRIPTOR');
  return Object.fromEntries(['kind','id','version','model','environment'].map(k=>[k,engine[k]]));
}
function executeOnce({adapter,artifactPath,variant,taskId,seed,budget}){
  const message=JSON.stringify({formatVersion:1,variant,taskId,seed,artifactPath,budget})+'\n';
  const start=process.hrtime.bigint();
  const child=spawnSync(process.execPath,[adapter],{
    input:message,encoding:'utf8',timeout:budget.maxDurationMs,maxBuffer:8192,
    shell:false,windowsHide:true,cwd:path.dirname(adapter),
    // No inherited API keys, NODE_OPTIONS, GitHub tokens, or other credentials.
    env:{},
  });
  const elapsed=Math.max(1,Math.ceil(Number(process.hrtime.bigint()-start)/1e6));
  let status='infrastructure-error',costUsd=0;
  if(child.error?.code==='ETIMEDOUT')status='timeout';
  else if(!child.error && child.status===0 && typeof child.stdout==='string' && Buffer.byteLength(child.stdout)<=8192){
    try{
      const value=JSON.parse(child.stdout);
      if(value && ['success','failure','timeout'].includes(value.status) &&
        typeof value.costUsd==='number' && Number.isFinite(value.costUsd) && value.costUsd>=0){
        status=value.costUsd>budget.maxCostUsd?'timeout':value.status;
        costUsd=Math.min(value.costUsd,budget.maxCostUsd);
      }
    }catch{/* malformed adapter response remains infrastructure-error */}
  }
  if(elapsed>=budget.maxDurationMs && status!=='infrastructure-error')status='timeout';
  const durationMs=Math.min(elapsed,budget.maxDurationMs);
  return {taskId,seed,status,durationMs,costUsd,
    evidenceSha256:sha([variant,taskId,seed,status,durationMs,costUsd,child.stdout??'',child.stderr??''].join('\0'))};
}
/**
 * Executes only an explicitly trusted adapter against owned/authorized artifact files.
 * An adapter may itself call a model, but FEA cannot enforce remote token spend or prove
 * that its answer is true. Adapter output is self-reported and must be independently audited.
 */
export function runPairedArena({suite,baselineFile,hardenedFile,adapterFile,engine,acknowledgeExecution=false}){
  validateSuite(suite);
  if(acknowledgeExecution!==true)throw Error('ARENA_EXPLICIT_EXECUTION_ACK_REQUIRED');
  if(suite.tasks.length*suite.minTrials*2>MAX_TRIALS)throw Error('ARENA_EXECUTION_TRIAL_LIMIT');
  if(suite.budget.maxDurationMs>60000)throw Error('ARENA_EXECUTION_DURATION_LIMIT');
  const adapter=checkedFile(adapterFile,1_000_000);
  if(path.extname(adapter)!=='.mjs')throw Error('ARENA_TRUSTED_NODE_ADAPTER_REQUIRED');
  const baselinePath=checkedFile(baselineFile,MAX_ARTIFACT_BYTES);
  const hardenedPath=checkedFile(hardenedFile,MAX_ARTIFACT_BYTES);
  if([baselinePath,hardenedPath].includes(adapter))throw Error('ARENA_ADAPTER_ARTIFACT_OVERLAP');
  const baselineDigest=sha(fs.readFileSync(baselinePath));
  const hardenedDigest=sha(fs.readFileSync(hardenedPath));
  if(baselineDigest===hardenedDigest)throw Error('ARENA_SAME_ARTIFACT');
  const descriptor=safeEngine(engine);
  const adapterDigest=sha(fs.readFileSync(adapter));
  const trials={baseline:[],hardened:[]};
  for(const task of suite.tasks)for(let seed=0;seed<suite.minTrials;seed++){
    // Reverse order on alternating seeds to avoid fixed order advantage.
    const order=seed%2?['hardened','baseline']:['baseline','hardened'];
    for(const variant of order){
      const artifactPath=variant==='baseline'?baselinePath:hardenedPath;
      trials[variant].push(executeOnce({adapter,artifactPath,variant,taskId:task.id,seed,budget:suite.budget}));
    }
  }
  const provenance={source:'local-trusted-adapter-executed',adapterSha256:adapterDigest,
    outcomeSource:'adapter-self-reported',evidenceValidated:false,remoteSpendEnforced:false,
    notice:'Not sandboxed. The adapter must be operator-trusted. No claim of real AI evaluation unless separately verified.'};
  const mkRun=variant=>({formatVersion:1,suiteId:suite.suiteId,variant,
    artifactDigest:variant==='baseline'?baselineDigest:hardenedDigest,
    engine:descriptor,trials:trials[variant],provenance});
  const baseline=mkRun('baseline'),hardened=mkRun('hardened');
  validateRun(baseline,suite,'baseline');
  validateRun(hardened,suite,'hardened');
  const comparison=compareArena(suite,baseline,hardened);
  comparison.provenance={...provenance,authorization:'operator-asserted-owned-or-authorized'};
  comparison.notice='Trusted local adapter was executed; outcomes, model use and cost are adapter-self-reported, not independently verified. Synthetic adapters are not AI resistance tests.';
  return {baseline,hardened,comparison};
}
