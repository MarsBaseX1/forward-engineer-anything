import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {snapshotArtifact} from '../src/release-trust.mjs';
import {recognizeInstaller,auditRelease,summarizeScanEvidence,summarizeNativeEvidence,auditMarkdown} from '../src/release-audit.mjs';
function tmp(t){const d=fs.mkdtempSync(path.join(os.tmpdir(),'fea-v044-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));return d;}
function formats(dir){
  const exe=Buffer.alloc(160);exe.write('MZ');exe.writeUInt32LE(80,60);exe.write('PE\0\0',80,'binary');
  const msi=Buffer.alloc(512);Buffer.from('d0cf11e0a1b11ae1','hex').copy(msi);msi.writeUInt16LE(65534,28);msi.writeUInt16LE(9,30);msi.writeUInt16LE(6,32);
  const dmg=Buffer.alloc(1024);dmg.write('koly',512);dmg.writeUInt32BE(4,516);dmg.writeUInt32BE(512,520);
  const pkg=Buffer.alloc(60);pkg.write('xar!');pkg.writeUInt16BE(28,4);pkg.writeUInt16BE(1,6);pkg.writeBigUInt64BE(32n,8);
  const files=[['a.exe',exe],['a.msi',msi],['a.dmg',dmg],['a.pkg',pkg]];
  for(const [name,bytes] of files)fs.writeFileSync(path.join(dir,name),bytes);
  return files.map(([name])=>path.join(dir,name));
}
test('EXE PE, MSI CFB, DMG UDIF and PKG XAR minimal headers recognized without extraction',t=>{
  for(const f of formats(tmp(t))){const r=recognizeInstaller(f);assert.equal(r.status,'pass');assert.equal(r.contentsInspected,false);}
});
test('mutated container header is fail and unknown extension unassessed',t=>{
  const root=tmp(t);
  for(const f of formats(root)){const bytes=fs.readFileSync(f);bytes[f.endsWith('.dmg')?512:0]^=255;fs.writeFileSync(f,bytes);assert.equal(recognizeInstaller(f).status,'fail');}
  fs.writeFileSync(path.join(root,'file.abc'),'content');
  assert.equal(recognizeInstaller(path.join(root,'file.abc')).status,'unassessed');
});
test('pinned manifest detects changed artifact, unsigned does not pass',t=>{
  const root=tmp(t),[exe]=formats(root);
  const pinned=snapshotArtifact(exe).snapshotSha256;
  const before=auditRelease(exe,{expectedSha256:pinned,publisher:false});
  assert.equal(before.checks.integrity.status,'pass');assert.equal(before.result,'unassessed');
  fs.appendFileSync(exe,'tampered');
  assert.equal(auditRelease(exe,{expectedSha256:pinned,publisher:false}).result,'fail');
});
test('absent independent pin does not generate positive trust result',t=>{
  const root=tmp(t),[exe]=formats(root);const r=auditRelease(exe,{publisher:false});
  assert.equal(r.checks.integrity.status,'unassessed');assert.equal(r.result,'unassessed');
  assert.equal(JSON.stringify(r).includes(root),false);
  assert.match(auditMarkdown(r),/UNASSESSED/);
});
test('scan evidence is fail on findings or incomplete coverage, never self-authorizes',()=>{
  const r={formatVersion:1,coverage:{complete:true,errors:[]},findings:[]};
  assert.equal(summarizeScanEvidence(r).status,'unassessed');
  assert.equal(summarizeScanEvidence({...r,findings:[{ruleId:'FEA001'}]}).status,'fail');
  assert.equal(summarizeScanEvidence({...r,coverage:{complete:false,errors:['IO']}}).status,'fail');
  assert.throws(()=>summarizeScanEvidence({}),/RELEASE_AUDIT_SCAN_EVIDENCE_INVALID/);
});
test('native evidence cannot self-attest and rejects malformed booleans',()=>{
  const r={formatVersion:1,kind:'native-electron-forge-package-evidence',platform:'win32',checks:{fuses:true,embeddedAsarHeaderHash:true,guiSmoke:true}};
  assert.equal(summarizeNativeEvidence(r).status,'unassessed');
  assert.equal(summarizeNativeEvidence({...r,checks:{...r.checks,guiSmoke:false}}).status,'fail');
  assert.throws(()=>summarizeNativeEvidence({...r,checks:{...r.checks,fuses:'yes'}}),/RELEASE_AUDIT_NATIVE_EVIDENCE_INVALID/);
});
test('CLI creates JSON and Markdown, returns exit 2 for unknown trust',t=>{
  const root=tmp(t),[exe]=formats(root),out=path.join(root,'reports');
  const cli=fileURLToPath(new URL('../scripts/release-audit.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[cli,exe,'--out',out],{encoding:'utf8'});
  assert.equal(r.status,2,r.stderr);assert.ok(fs.existsSync(path.join(out,'release-audit.md')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'release-audit.json'),'utf8')).result,'unassessed');
  const invalid=spawnSync(process.execPath,[cli,exe,'--out',out,'--invalid','x'],{encoding:'utf8'});
  assert.equal(invalid.status,1);
});
test('symlinks and malformed pins are denied',t=>{
  const root=tmp(t),[exe]=formats(root);
  assert.throws(()=>auditRelease(exe,{expectedSha256:'bogus'}),/TRUST_EXPECTED_HASH_INVALID/);
  const link=path.join(root,'link.exe');
  try{fs.symlinkSync(exe,link);}catch(e){if(['EPERM','EACCES'].includes(e.code))return;throw e;}
  assert.throws(()=>recognizeInstaller(link),/RELEASE_AUDIT_REGULAR_FILE_REQUIRED/);
});
