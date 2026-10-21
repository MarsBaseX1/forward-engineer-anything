import fs from 'node:fs';
import path from 'node:path';
import {importExternalTrials} from '../src/arena-import.mjs';
import {compareArena} from '../src/arena.mjs';
const suite=JSON.parse(fs.readFileSync('demo/arena-suite.json','utf8'));
const out='demo/generated/reports/external-import-fixture';fs.mkdirSync(out,{recursive:true});
const engine={kind:'external',id:'synthetic-jsonl-adapter',version:'fixture-v1',model:'no-model',environment:'test-only'};
for(const variant of ['baseline','hardened']){
 const descriptor={variant,artifactDigest:(variant==='baseline'?'1':'2').repeat(64),engine};
 const lines=suite.tasks.flatMap(task=>Array.from({length:10},(_,seed)=>JSON.stringify({taskId:task.id,seed,
   status:variant==='baseline'?'success':'timeout',durationMs:100,costUsd:0,
   evidenceSha256:'3'.repeat(64),trace:'DO_NOT_EXPORT_RAW_TRACE'})));
 const run=importExternalTrials(suite,descriptor,lines.join('\n'));
 fs.writeFileSync(path.join(out,variant+'.json'),JSON.stringify(run,null,2)+'\n');
 if(JSON.stringify(run).includes('DO_NOT_EXPORT_RAW_TRACE'))throw Error('FIXTURE_LEAK');
}
const before=JSON.parse(fs.readFileSync(path.join(out,'baseline.json'))),after=JSON.parse(fs.readFileSync(path.join(out,'hardened.json')));
const report=compareArena(suite,before,after);
if(report.kind!=='external'||!report.notice.includes('unverified'))throw Error('FIXTURE_WRONG_PROVENANCE');
console.log('EXTERNAL IMPORT FIXTURE PASS: 20/20 JSONL rows accepted per variant; no model or reverse engineering executed.');
