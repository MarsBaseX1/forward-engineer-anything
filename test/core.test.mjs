import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {DEFAULT_CONFIG,VERSION,scanDirectory,verifyReport,compareReports,comparisonMarkdown,validateConfig} from '../src/core.mjs';
function fixture() {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'fea-test-'));
  const input=path.join(root,'release');fs.mkdirSync(input);
  const put=(name,content)=>{const p=path.join(input,name);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,content);};
  const cleanup=()=>fs.rmSync(root,{recursive:true,force:true});
  return {root,input,put,cleanup};
}
test('scans exposure categories including new anti-REA rules, never writes raw paths, secrets or file contents',t=>{
  const f=fixture();t.after(f.cleanup);
  const secret='SYNTHETIC-SENSITIVE-VALUE-12345';
  f.put('debug.pdb','symbols');f.put('internal-config.json','{"INTERNAL_API_URL":"'+secret+'"}');
  f.put('credentials.pem','-----BEGIN PRIVATE KEY-----\n'+secret+'\n-----END PRIVATE KEY-----');
  f.put('main.js.map','{}');f.put('main.js','//# sourceMappingURL=main.js.map');
  f.put('__tests__/a.test.js','ok');
  f.put('auth.js','function isPremium(){return true;}');
  f.put('config.js','const api_key = "sk-abcdef1234567890abcdef";');
  f.put('logic.js','// TODO: calculatePrice for enterprise');
  f.put('state.js','window.__INITIAL_STATE__ = {user: {token: "abc"}};');
  const result=scanDirectory(f.input,DEFAULT_CONFIG,{out:path.join(f.root,'reports')});
  assert.equal(result.coverage.complete,true);
  assert.deepEqual([...new Set(result.findings.map(f=>f.ruleId))].sort(),['FEA001','FEA002','FEA003','FEA004','FEA005','FEA006','FEA007','FEA008','FEA009']);
  const json=JSON.stringify(result);assert.equal(json.includes(secret),false);assert.equal(json.includes('credentials.pem'),false);
  assert.equal(verifyReport(result,DEFAULT_CONFIG).ok,false);
});
test('clean build passes and compare produces useful differences',t=>{
  const f=fixture();t.after(f.cleanup);f.put('main.cjs','console.log("safe")');
  const clean=scanDirectory(f.input,DEFAULT_CONFIG);
  assert.equal(verifyReport(clean,DEFAULT_CONFIG).ok,true);
  f.put('secret.env','INTERNAL_API_URL=x');
  const dirty=scanDirectory(f.input,DEFAULT_CONFIG);
  const c=compareReports(dirty,clean);
  assert.ok(c.resolved>0);assert.equal(c.introduced,0);assert.match(comparisonMarkdown(c),/Observed findings only/);
});
test('deterministic findings, paths are hashed and do not disclose odd file names',t=>{
  const f=fixture();t.after(f.cleanup);f.put('private-credential-example.pem','-----BEGIN PRIVATE KEY-----');
  const a=scanDirectory(f.input,DEFAULT_CONFIG);const b=scanDirectory(f.input,DEFAULT_CONFIG);
  assert.deepEqual(a.findings,b.findings);assert.equal(a.inputDigest,b.inputDigest);
  assert.equal(JSON.stringify(a).includes('private-credential'),false);
});
test('rejects output inside scanned input',t=>{
  const f=fixture();t.after(f.cleanup);f.put('index.js','ok');
  assert.throws(()=>scanDirectory(f.input,DEFAULT_CONFIG,{out:path.join(f.input,'reports')}),/outside/);
});
test('symlink is incomplete and cannot pass policy (where supported)',t=>{
  const f=fixture();t.after(f.cleanup);f.put('ok.js','safe');
  try{fs.symlinkSync('ok.js',path.join(f.input,'shortcut.js'));}catch(e){if(['EPERM','EACCES'].includes(e.code))return;throw e;}
  const r=scanDirectory(f.input,DEFAULT_CONFIG);
  assert.equal(r.coverage.complete,false);assert.ok(r.coverage.errors.includes('SYMLINK_UNSUPPORTED'));
  assert.equal(verifyReport(r,DEFAULT_CONFIG).ok,false);
});
test('over-limit files are incomplete, never silently skipped',t=>{
  const f=fixture();t.after(f.cleanup);f.put('large.js','0123456789');
  const cfg=structuredClone(DEFAULT_CONFIG);cfg.limits.maxFileBytes=2;
  const r=scanDirectory(f.input,cfg);
  assert.equal(r.coverage.complete,false);assert.ok(r.coverage.errors.includes('FILE_BYTE_LIMIT'));
  assert.equal(verifyReport(r,cfg).ok,false);
  assert.throws(()=>compareReports(r,r),/incomplete/);
});
test('exceptions require ownership and expiry; expired exception fails',t=>{
  const f=fixture();t.after(f.cleanup);f.put('main.js.map','{}');
  const r=scanDirectory(f.input,DEFAULT_CONFIG),cfg=structuredClone(DEFAULT_CONFIG);
  cfg.policy.exceptions=[{ruleId:'FEA001',pathId:r.findings[0].pathId,owner:'maintainer',reason:'known synthetic example',expires:'2026-12-31'}];
  assert.equal(verifyReport(r,cfg,new Date('2026-10-21')).ok,true);
  assert.equal(verifyReport(r,cfg,new Date('2027-01-01')).ok,false);
  cfg.policy.exceptions[0].owner='';assert.throws(()=>validateConfig(cfg),/exception/);
});
test('rejects mismatched stages and missing rule coverage',t=>{
  const f=fixture();t.after(f.cleanup);f.put('main.js','ok');const r=scanDirectory(f.input,DEFAULT_CONFIG);
  const alt=structuredClone(DEFAULT_CONFIG);alt.inputStage='developer-extracted';
  assert.equal(verifyReport(r,alt).ok,false);
  const broken=structuredClone(r);broken.coverage.ruleIds.pop();
  assert.equal(verifyReport(broken,DEFAULT_CONFIG).ok,false);
  assert.throws(()=>compareReports(broken,r),/Incompatible/);
});
test('verify rejects reports created by a different scanner version',t=>{
  const f=fixture();t.after(f.cleanup);f.put('main.js','ok');
  const report=scanDirectory(f.input,DEFAULT_CONFIG);
  assert.equal(report.scannerVersion,VERSION);
  report.scannerVersion='0.4.4';
  const result=verifyReport(report,DEFAULT_CONFIG);
  assert.equal(result.ok,false);
  assert(result.problems.includes('SCANNER_VERSION_MISMATCH'));
  const current=scanDirectory(f.input,DEFAULT_CONFIG);
  assert.throws(()=>compareReports(report,current),/scanner version/i);
});
