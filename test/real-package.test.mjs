import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {validateFuseStates,verifyHeaderIntegrity,validateSmokeResult,locateFixture} from '../src/real-package.mjs';
const keys={RunAsNode:0,EnableNodeOptionsEnvironmentVariable:2,EnableNodeCliInspectArguments:3,EnableEmbeddedAsarIntegrityValidation:4,OnlyLoadAppFromAsar:5};
const SHA='9'.repeat(64);
test('fuse wire requires both protections and disallows Node entry points',()=>{
  const wire={version:'1',0:0x30,2:0x30,3:0x30,4:0x31,5:0x31};
  assert.equal(validateFuseStates(wire,{FuseV1Options:keys}).ok,true);
  assert.equal(validateFuseStates({...wire,5:0x30},{FuseV1Options:keys}).ok,false);
  assert.equal(validateFuseStates({...wire,4:0x90},{FuseV1Options:keys}).ok,false);
  assert.throws(()=>validateFuseStates({...wire,version:'2'},{FuseV1Options:keys}),/REAL_FUSE_VERSION/);
});
test('Windows PE integrity metadata checks exact archive path, algorithm and hash',()=>{
  const sample=[{file:'resources\\app.asar',alg:'sha256',value:SHA}];
  assert.equal(verifyHeaderIntegrity({headerSha256:SHA,embeddedRecords:sample,platform:'win32'}).ok,true);
  assert.equal(verifyHeaderIntegrity({headerSha256:'a'.repeat(64),embeddedRecords:sample,platform:'win32'}).ok,false);
  assert.throws(()=>verifyHeaderIntegrity({headerSha256:SHA,embeddedRecords:[...sample,...sample],platform:'win32'}),/DUPLICATE/);
  assert.throws(()=>verifyHeaderIntegrity({headerSha256:SHA,embeddedRecords:[{...sample[0],alg:'md5'}],platform:'win32'}),/INVALID/);
});
test('macOS plist integrity metadata is checked independently of the ASAR file',()=>{
  assert.equal(verifyHeaderIntegrity({headerSha256:SHA,embeddedRecords:{file:'Resources/app.asar',algorithm:'SHA256',hash:SHA},platform:'darwin'}).ok,true);
  assert.throws(()=>verifyHeaderIntegrity({headerSha256:SHA,embeddedRecords:{file:'Other/app.asar',algorithm:'SHA256',hash:SHA},platform:'darwin'}),/MISSING/);
});
test('smoke result requires explicit renderer DOM marker and success',()=>{
  const result={formatVersion:1,ok:true,marker:'FEA_PACKAGED_GUI_OK',reason:'page-loaded',platform:'win32'};
  assert.equal(validateSmokeResult(result,'win32').ok,true);
  assert.throws(()=>validateSmokeResult({...result,marker:'forged'},'win32'),/REAL_GUI_SMOKE_FAILED/);
  assert.throws(()=>validateSmokeResult(result,'darwin'),/REAL_GUI_SMOKE_FAILED/);
});
test('artifact discovery fails closed on ambiguity, symlinks or missing executables',t=>{
  const folder=fs.mkdtempSync(path.join(os.tmpdir(),'fea-real-'));
  t.after(()=>fs.rmSync(folder,{recursive:true,force:true}));
  assert.throws(()=>locateFixture(folder,'win32'),/REAL_ARTIFACT_NOT_UNIQUE/);
  for(const name of ['first','second']){
    const base=path.join(folder,name);fs.mkdirSync(path.join(base,'resources'),{recursive:true});
    fs.writeFileSync(path.join(base,'resources','app.asar'),'placeholder');
    fs.writeFileSync(path.join(base,'FEAElectronSmoke.exe'),'MZ');
  }
  assert.throws(()=>locateFixture(folder,'win32'),/REAL_ARTIFACT_NOT_UNIQUE/);
  fs.rmSync(path.join(folder,'second'),{recursive:true,force:true});
  assert.ok(locateFixture(folder,'win32').binary.endsWith('.exe'));
  try{fs.rmSync(path.join(folder,'first','FEAElectronSmoke.exe'));fs.symlinkSync(path.join(folder,'first','resources','app.asar'),path.join(folder,'first','FEAElectronSmoke.exe'));}
  catch(e){if(e.code==='EPERM'||e.code==='EACCES')return;throw e;}
  assert.throws(()=>locateFixture(folder,'win32'),/REAL_ARTIFACT_NOT_UNIQUE/);
});
