import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {toSarif,SARIF_ANCHOR} from '../src/sarif.mjs';
import {scanDirectory,DEFAULT_CONFIG,RULES} from '../src/core.mjs';
const safeConfig=structuredClone(DEFAULT_CONFIG);
const digest=s=>crypto.createHash('sha256').update(s).digest('hex');
function withTree(t,files){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'fea-sarif-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  for(const [relative,body] of Object.entries(files)){
    fs.mkdirSync(path.dirname(path.join(dir,relative)),{recursive:true});
    fs.writeFileSync(path.join(dir,relative),body);
  }
  return dir;
}
test('SARIF produces valid catalog, stable findings and sanitized fixed anchor',t=>{
  const marker='-----BEGIN PRIVATE KEY-----\nSYNTHETIC-SARIF-TOKEN\n';
  const root=withTree(t,{'secret/internal-config.json':JSON.stringify({INTERNAL_API_URL:'private.example.com'}), 'name\u00e9.pem':marker,'secret/app.js.map':'{}'});
  const report=scanDirectory(root,safeConfig);
  const sarif=toSarif(report), serialized=JSON.stringify(sarif);
  assert.equal(sarif.version,'2.1.0');
  assert.equal(sarif.runs[0].tool.driver.rules.length,Object.keys(RULES).length);
  assert.ok(sarif.runs[0].results.length>=3);
  for(const x of sarif.runs[0].results){
    assert.equal(x.locations.length,1);
    assert.equal(x.locations[0].physicalLocation.artifactLocation.uri,SARIF_ANCHOR);
    assert.equal(x.locations[0].physicalLocation.region.startLine,1);
    assert.ok(x.partialFingerprints.primaryLocationLineHash);
  }
  assert.equal(serialized.includes('SYNTHETIC-SARIF-TOKEN'),false);
  assert.equal(serialized.includes('private.example.com'),false);
  assert.equal(serialized.includes('internal-config.json'),false);
  assert.equal(serialized.includes(root),false);
  assert.deepEqual(toSarif(report),sarif);
});
test('SARIF exports an empty results array for a clean, complete scan',t=>{
  const root=withTree(t,{'index.js':'console.log(1)'});
  const report=scanDirectory(root,safeConfig);
  const sarif=toSarif(report);
  assert.equal(sarif.runs[0].results.length,0);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful,true);
});
test('SARIF fails closed on incomplete coverage and missing rule coverage',t=>{
  const root=withTree(t,{'index.js':'console.log(1)'});
  const report=scanDirectory(root,safeConfig);
  report.coverage.complete=false;
  assert.throws(()=>toSarif(report),/SARIF_INCOMPLETE_COVERAGE/);
  report.coverage.complete=true;
  report.coverage.ruleIds.pop();
  assert.throws(()=>toSarif(report),/SARIF_INCOMPLETE_COVERAGE/);
});
test('SARIF rejects duplicates and excessive result cardinality',t=>{
  const root=withTree(t,{'index.js.map':'{}'}), r=scanDirectory(root,safeConfig);
  r.findings.push({...r.findings[0]});
  assert.throws(()=>toSarif(r),/SARIF_DUPLICATE_FINDING/);
  r.findings=Array.from({length:5001},(_,i)=>({ruleId:'FEA001',pathId:digest(String(i)).slice(0,16),fingerprint:digest('finding'+i).slice(0,20)}));
  assert.throws(()=>toSarif(r),/SARIF_RESULTS_LIMIT/);
});
test('SARIF ignores injected untrusted report messages and extra properties',t=>{
  const root=withTree(t,{'internal.json': 'PRIVATE_API_KEY=SECRET'});
  const report=scanDirectory(root,safeConfig);
  report.findings[0].message='PRIVATE-USER-TOKEN';
  report.findings[0].extra={token:'REALLY-SECRET'};
  report.scannerVersion='evil-random-version';
  const content=JSON.stringify(toSarif(report));
  assert.equal(content.includes('PRIVATE-USER-TOKEN'),false);
  assert.equal(content.includes('REALLY-SECRET'),false);
  assert.equal(content.includes('evil-random-version'),false);
});
test('sanitized outputs share catalog levels and fingerprint stability across report metadata changes',t=>{
  const root=withTree(t,{'index.js.map':'{}'}), report=scanDirectory(root,safeConfig);
  const before=toSarif(report);
  report.generatedAt=new Date(2030,1,1).toISOString();
  const after=toSarif(report);
  assert.deepEqual(before,after);
});
