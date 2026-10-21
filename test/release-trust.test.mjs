import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {snapshotArtifact,verifyPublisher,assessWindowsOutput,assessMacOutputs} from '../src/release-trust.mjs';
const pin='A'.repeat(40),team='ABC1234XYZ';
function setup(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'fea-trust-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
test('manifest hash is repeatable and contains no plain file names',t=>{
 const root=setup(t),p=path.join(root,'v1');fs.mkdirSync(p);fs.writeFileSync(path.join(p,'safe secret.txt'),'hello');
 const a=snapshotArtifact(p),b=snapshotArtifact(p,{expectedSha256:a.snapshotSha256});
 assert.equal(a.snapshotSha256,b.snapshotSha256);assert.equal(b.digestMatch,true);
 assert.equal(JSON.stringify(a).includes('safe secret.txt'),false);assert.equal(a.files,1);
});
test('modified content fails independent SHA-256 pin',t=>{
 const root=setup(t),p=path.join(root,'bundle.exe');fs.writeFileSync(p,'one');
 const before=snapshotArtifact(p);
 fs.writeFileSync(p,'two');const after=snapshotArtifact(p,{expectedSha256:before.snapshotSha256});
 assert.equal(after.digestMatch,false);
});
test('manifest rejects invalid digest pin and empty folders',t=>{
 const root=setup(t);assert.throws(()=>snapshotArtifact(root,{expectedSha256:'0'}),/TRUST_EXPECTED_HASH_INVALID/);
 assert.throws(()=>snapshotArtifact(root),/TRUST_EMPTY_ARTIFACT/);
});
test('symlink and hardlink are not treated as verified content',t=>{
 const root=setup(t),p=path.join(root,'a');fs.mkdirSync(p);const target=path.join(root,'f');fs.writeFileSync(target,'test');
 try{fs.symlinkSync(target,path.join(p,'link'));}catch(e){if(['EPERM','EACCES'].includes(e.code))return;throw e;}
 assert.throws(()=>snapshotArtifact(p),/TRUST_SYMLINK_UNSUPPORTED/);
 fs.unlinkSync(path.join(p,'link'));fs.linkSync(target,path.join(p,'hard'));
 assert.throws(()=>snapshotArtifact(p),/TRUST_NONREGULAR_UNSUPPORTED/);
});
test('Windows signature status requires both OS validity and pinned identity',()=>{
 assert.equal(assessWindowsOutput({status:'Valid',thumbprint:pin},pin).passed,true);
 assert.equal(assessWindowsOutput({status:'Valid',thumbprint:'B'.repeat(40)},pin).passed,false);
 assert.equal(assessWindowsOutput({status:'NotSigned',thumbprint:pin},pin).passed,false);
 assert.throws(()=>assessWindowsOutput({},'bad'),/TRUST_WINDOWS_SIGNER_PIN_REQUIRED/);
});
test('macOS verification requires trust, team and stapled notarization',()=>{
 const ok={codesign:true,details:`Identifier=com.example.app\nTeamIdentifier=${team}\n`,gatekeeper:true,stapled:true};
 assert.equal(assessMacOutputs(ok,team).passed,true);
 assert.equal(assessMacOutputs({...ok,stapled:false},team).passed,false);
 assert.equal(assessMacOutputs({...ok,gatekeeper:false},team).passed,false);
 assert.equal(assessMacOutputs({...ok,details:'TeamIdentifier=OTHERTEAM1'},team).passed,false);
 assert.throws(()=>assessMacOutputs(ok,'BAD'),/TRUST_MAC_TEAM_PIN_REQUIRED/);
});
test('non-native host, missing pin and bad inputs can never pass',t=>{
 const root=setup(t),exe=path.join(root,'app.exe');fs.writeFileSync(exe,'MZ');
 const app=path.join(root,'App.app');fs.mkdirSync(app);
 const foreign=process.platform==='win32'?'darwin':'win32';
 const item=foreign==='win32'?exe:app;
 const unassessed=verifyPublisher(item,{platform:foreign,expectedThumbprint:pin,expectedTeamId:team});
 assert.equal(unassessed.status,'unassessed');assert.equal(unassessed.passed,false);
 const native=process.platform==='win32'?verifyPublisher(exe,{platform:'win32'}):process.platform==='darwin'?verifyPublisher(app,{platform:'darwin'}):null;
 if(native)assert.equal(native.passed,false);
});
test('opaque installer file hashing is possible without claiming installer parsing',t=>{
 const root=setup(t),msi=path.join(root,'app.msi');fs.writeFileSync(msi,Buffer.from('not a real installer'));
 const report=snapshotArtifact(msi);assert.equal(report.inputKind,'opaque-file');
 assert.match(report.notice,/no installer payload/i);
});
