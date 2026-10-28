import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {scanAsar,parseUniqueJson} from '../src/asar.mjs';
import {planForge} from '../src/protect.mjs';
import {verifyAuthenticode} from '../src/signature.mjs';
import {DEFAULT_CONFIG,verifyReport} from '../src/core.mjs';
function temp(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'fea-v02-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
function asar(root,tree,content=Buffer.alloc(0)) {
  const json=Buffer.from(typeof tree==='string'?tree:JSON.stringify(tree));
  // Standard Chromium Pickle: payload length, then a length-prefixed UTF-8 string.
  const payloadLength=(4+json.length+3)&~3;
  const header=Buffer.alloc(4+payloadLength);
  header.writeUInt32LE(payloadLength,0);
  header.writeUInt32LE(json.length,4);
  json.copy(header,8);
  const size=Buffer.alloc(8);size.writeUInt32LE(4,0);size.writeUInt32LE(header.length,4);
  const file=path.join(root,'app.asar');fs.writeFileSync(file,Buffer.concat([size,header,content]));return file;
}
test('asar detects actual embedded risks without disclosing filenames or contents',t=>{
  const root=temp(t),data=Buffer.from('//# sourceMappingURL=index.js.map\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC-SECRET');
  const file=asar(root,{files:{'internal.js':{offset:'0',size:data.length}}},data);
  const r=scanAsar(file,DEFAULT_CONFIG,{out:path.join(root,'reports')});
  assert.equal(r.coverage.complete,true);assert.deepEqual(r.findings.map(x=>x.ruleId),['FEA001','FEA002','FEA003']);
  assert.equal(JSON.stringify(r).includes('SYNTHETIC'),false);assert.equal(JSON.stringify(r).includes('internal.js'),false);
  assert.equal(verifyReport(r,DEFAULT_CONFIG).ok,false);
});
test('clean ASAR reports policy success',t=>{
  const root=temp(t),data=Buffer.from('console.log(1)');
  const r=scanAsar(asar(root,{files:{'index.js':{offset:'0',size:data.length}}},data),DEFAULT_CONFIG);
  assert.equal(r.coverage.complete,true);assert.equal(verifyReport(r,DEFAULT_CONFIG).ok,true);
});
test('malformed, duplicate entries and unsafe paths fail closed',t=>{
  const root=temp(t);
  for(const bad of ['{"files":{"a.js":{"offset":"0","size":0},"a.js":{"offset":"0","size":0}}}',
   {files:{'../outside':{offset:'0',size:0}}},{files:{'a':{link:'elsewhere'}}},
   {files:{'a':{offset:'900000000',size:10}}}]){
    const r=scanAsar(asar(root,bad),DEFAULT_CONFIG);
    assert.equal(r.coverage.complete,false,JSON.stringify(bad));assert.equal(verifyReport(r,DEFAULT_CONFIG).ok,false);
  }
  assert.throws(()=>parseUniqueJson('{"a":1,"a":2}'),/DUPLICATE/);
});
test('ASAR unpacked sidecars scanned but symlinks and absent sidecars fail closed',t=>{
  const root=temp(t),data=Buffer.from('//# sourceMappingURL=hi.js.map');
  const file=asar(root,{files:{'index.js':{unpacked:true,size:data.length}}});
  let r=scanAsar(file,DEFAULT_CONFIG);assert.equal(r.coverage.complete,false);
  fs.mkdirSync(file+'.unpacked');fs.writeFileSync(path.join(file+'.unpacked','index.js'),data);
  r=scanAsar(file,DEFAULT_CONFIG);assert.equal(r.coverage.complete,true);assert.equal(r.findings[0].ruleId,'FEA001');
  fs.rmSync(path.join(file+'.unpacked','index.js'));
  try{fs.symlinkSync(path.join(root,'external.js'),path.join(file+'.unpacked','index.js'));}catch(e){if(e.code==='EPERM'||e.code==='EACCES')return;throw e;}
  assert.equal(scanAsar(file,DEFAULT_CONFIG).coverage.complete,false);
});
test('ASAR checks header and entry bounds and integrity',t=>{
  const root=temp(t),data=Buffer.from('abcdef');
  const cases=[{files:{a:{offset:'0',size:data.length,integrity:{algorithm:'SHA256',hash:'0'.repeat(64)}}}},
    {files:{a:{offset:'0',size:99}}}];
  for(const tree of cases)assert.equal(scanAsar(asar(root,tree,data),DEFAULT_CONFIG).coverage.complete,false);
  const hash=crypto.createHash('sha256').update(data).digest('hex');
  const r=scanAsar(asar(root,{files:{a:{offset:'0',size:data.length,integrity:{algorithm:'SHA256',hash}}}},data),DEFAULT_CONFIG);
  assert.equal(r.coverage.complete,true);
});
test('Forge plan analyzes JSON config without executing code or modifying project',t=>{
  const root=temp(t);fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({devDependencies:{'@electron-forge/cli':'7.4.0'},config:{forge:{packagerConfig:{asar:false}}}}));
  fs.writeFileSync(path.join(root,'forge.config.js'),'throw Error("must not run")');
  const before=fs.readFileSync(path.join(root,'package.json'),'utf8');
  const plan=planForge(root);
  assert.equal(plan.supported,true);assert.equal(plan.applied,false);assert.ok(plan.notes.some(n=>n.includes('asar')));
  assert.equal(fs.readFileSync(path.join(root,'package.json'),'utf8'),before);
});
test('Authenticode off Windows remains unassessed; malformed thumbprints rejected',t=>{
  const root=temp(t),file=path.join(root,'fake.exe');fs.writeFileSync(file,Buffer.from('MZ'));
  assert.throws(()=>verifyAuthenticode(file,{expectedThumbprint:'WRONG'}),/thumbprint/);
  if(process.platform!=='win32') {
    const result=verifyAuthenticode(file);assert.equal(result.assessed,false);assert.equal(result.valid,false);
  }
});
