import fs from 'node:fs';
import crypto from 'node:crypto';
import {validateRun,validateSuite} from './arena.mjs';

// External agent adapters write JSONL with digest-only evidence references.
// This import NEVER launches agent commands, opens trace files, or asserts trace authenticity.
const SHA=/^[a-f0-9]{64}$/;
export function importExternalTrials(suite,descriptor,trialJsonl){
  validateSuite(suite);
  if(typeof trialJsonl!=='string'||Buffer.byteLength(trialJsonl)>2_000_000)throw Error('ARENA_EXTERNAL_LOG_TOO_LARGE');
  if(!descriptor || !['baseline','hardened'].includes(descriptor.variant) || !SHA.test(descriptor.artifactDigest??'') ||
     !descriptor.engine || descriptor.engine.kind!=='external')throw Error('ARENA_EXTERNAL_DESCRIPTOR_INVALID');
  const trials=[];
  for(const line of trialJsonl.split(/\r?\n/).filter(Boolean)){
    let row;
    try{row=JSON.parse(line);}catch{throw Error('ARENA_EXTERNAL_JSONL_INVALID');}
    if(!row || !SHA.test(row.evidenceSha256??''))throw Error('ARENA_EXTERNAL_EVIDENCE_DIGEST_REQUIRED');
    // Whitelist fields: don't copy prompts, private trace contents, paths, tokens, or agent responses.
    trials.push({taskId:row.taskId,seed:row.seed,status:row.status,durationMs:row.durationMs,costUsd:row.costUsd,evidenceSha256:row.evidenceSha256});
  }
  const run={formatVersion:1,suiteId:suite.suiteId,variant:descriptor.variant,
    artifactDigest:descriptor.artifactDigest,engine:descriptor.engine,trials,
    provenance:{source:'external-self-reported',logSha256:crypto.createHash('sha256').update(trialJsonl).digest('hex'),evidenceValidated:false}};
  validateRun(run,suite,descriptor.variant);
  return run;
}
export function importExternalFiles({suiteFile,descriptorFile,trialsFile}){
  const load=(p,limit)=>{
    const s=fs.lstatSync(p);
    if(!s.isFile()||s.isSymbolicLink()||s.size>limit)throw Error('ARENA_EXTERNAL_INPUT_UNSUPPORTED');
    return fs.readFileSync(p,'utf8');
  };
  return importExternalTrials(JSON.parse(load(suiteFile,100000)),JSON.parse(load(descriptorFile,100000)),load(trialsFile,2_000_000));
}
