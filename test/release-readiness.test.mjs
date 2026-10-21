import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {packDemoAsar} from '../demo/pack-asar.mjs';
import {evaluateFuseCompatibility,inspectUnpackedRelease} from '../src/release-readiness.mjs';
import {DEFAULT_CONFIG} from '../src/core.mjs';
import {assertStartupContract} from '../demo/release-readiness.mjs';
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function temp(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'fea-v041-'));t.after(()=>fs.rmSync(root,{force:true,recursive:true}));return root;}
const write=(p,v)=>{fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,v);};
function project(t,version='33.4.11',forge='7.4.0'){
  const root=temp(t);
  write(path.join(root,'package.json'),JSON.stringify({devDependencies:{electron:version,'@electron-forge/cli':forge},config:{forge:{packagerConfig:{asar:true}}}}));
  return root;
}
function release(t,platform='win32'){
  const root=temp(t),actual=platform==='win32'?path.join(root,'win-unpacked'):path.join(root,'Demo.app');
  fs.mkdirSync(actual,{recursive:true});
  if(platform==='win32'){
    const pe=Buffer.alloc(256);pe.write('MZ');pe.writeUInt32LE(128,0x3c);pe.write('PE\0\0',128,'binary');
    write(path.join(actual,'Demo.exe'),pe);
  }else{write(path.join(actual,'Contents/MacOS/Demo'),Buffer.from('cffaedfe','hex'));}
  const source=path.join(root,'source');fs.mkdirSync(source);write(path.join(source,'index.js'),'console.log(1)');
  const archive=path.join(actual,platform==='win32'?'resources/app.asar':'Contents/Resources/app.asar');
  packDemoAsar(source,archive);
  return {root,actual,source,archive};
}
test('Electron >=30 Windows and >=16 macOS declaration thresholds',t=>{
  const projectDir=project(t);
  assert.equal(evaluateFuseCompatibility(projectDir,'win32').status,'compatible-declarations');
  assert.equal(evaluateFuseCompatibility(projectDir,'darwin').status,'compatible-declarations');
  const pkgFile=path.join(projectDir,'package.json'),pkg=JSON.parse(fs.readFileSync(pkgFile));
  pkg.devDependencies.electron='29.4.0';write(pkgFile,JSON.stringify(pkg));
  assert.equal(evaluateFuseCompatibility(projectDir,'win32').status,'unassessed');
  assert.equal(evaluateFuseCompatibility(projectDir,'darwin').status,'compatible-declarations');
  pkg.devDependencies.electron='15.0.0';write(pkgFile,JSON.stringify(pkg));
  assert.equal(evaluateFuseCompatibility(projectDir,'darwin').status,'unassessed');
});
test('Forge 7.4.0 minimum and unpinned versions do not falsely pass',t=>{
  const projectDir=project(t,'33.4.11','7.3.9');
  assert.ok(evaluateFuseCompatibility(projectDir,'win32').blockers.includes('FORGE_ASAR_INTEGRITY_UNSUPPORTED'));
  const pkgFile=path.join(projectDir,'package.json'),pkg=JSON.parse(fs.readFileSync(pkgFile));
  pkg.devDependencies['@electron-forge/cli']='^7.4.0';write(pkgFile,JSON.stringify(pkg));
  assert.ok(evaluateFuseCompatibility(projectDir,'win32').blockers.includes('FORGE_VERSION_UNPINNED_OR_MISSING'));
});
test('disabled ASAR or dynamic Forge config never claims validated fuses',t=>{
  const projectDir=project(t);
  const pkgFile=path.join(projectDir,'package.json'),pkg=JSON.parse(fs.readFileSync(pkgFile));
  pkg.config.forge.packagerConfig.asar=false;write(pkgFile,JSON.stringify(pkg));
  assert.ok(evaluateFuseCompatibility(projectDir,'win32').blockers.includes('ASAR_NOT_CONFIRMED_ENABLED'));
  write(path.join(projectDir,'forge.config.js'),'throw Error("should not execute")');
  assert.ok(evaluateFuseCompatibility(projectDir,'win32').blockers.includes('FORGE_CONFIG_UNASSESSED'));
});
test('win32 unpacked ASAR and recognized PE header passes static checks',t=>{
  const {actual,archive}=release(t);const expected=hash(archive);
  const r=inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG,expectedAsarSha256:expected});
  assert.equal(r.result.status,'static-checks-pass');assert.equal(r.result.checks.asarDigestMatches,true);
  assert.equal(r.result.unassessed.includes('binary-fuse-bits'),true);
  assert.equal(r.result.unassessed.includes('GUI-startup'),true);
  assert.equal(r.scan.findings.length,0);
});
test('macOS .app static Mach-O header and ASAR path inspected',t=>{
  const {actual}=release(t,'darwin');const r=inspectUnpackedRelease(actual,{platform:'darwin',config:DEFAULT_CONFIG});
  assert.equal(r.result.status,'static-checks-pass');assert.equal(r.result.checks.asarDigestPinned,false);
});
test('expected ASAR digest mismatch fails closed',t=>{
  const {actual}=release(t);const r=inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG,expectedAsarSha256:'0'.repeat(64)});
  assert.equal(r.result.status,'fail');assert.ok(r.result.issues.includes('ASAR_EXPECTED_DIGEST_MISMATCH'));
});
test('binary header is checked, not assumed from extension',t=>{
  const {actual}=release(t);write(path.join(actual,'Demo.exe'),'not-a-pe');
  const r=inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG});
  assert.ok(r.result.issues.includes('EXECUTABLE_HEADER_UNRECOGNIZED'));
});
test('unsafe symlinks and missing ASAR rejected',t=>{
  const {actual,archive}=release(t);fs.rmSync(archive);const outside=path.join(path.dirname(actual),'fake.asar');write(outside,'fake');
  try{fs.symlinkSync(outside,archive);}catch(e){if(['EPERM','EACCES'].includes(e.code))return;throw e;}
  assert.throws(()=>inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG}),/SYMLINK/);
});
test('security findings prevent false clean release',t=>{
  const {actual,archive,source}=release(t);write(path.join(source,'secrets.json'),'-----BEGIN PRIVATE KEY-----');packDemoAsar(source,archive);
  const r=inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG});
  assert.equal(r.result.status,'fail');assert.ok(r.result.issues.includes('ASAR_POLICY_FAILED'));
});
test('malformed archive fails closed without leaking source paths',t=>{
  const {actual,archive}=release(t);write(archive,'broken');
  const r=inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG});
  assert.equal(r.result.status,'fail');assert.ok(r.result.issues.includes('ASAR_SCAN_INCOMPLETE'));
  assert.equal(JSON.stringify(r.result).includes(actual),false);
});
test('isolated startup contract exercises owned Electron main entry with fake API',t=>{
  const source=fs.readFileSync('demo/electron-app/main.cjs','utf8');
  assert.equal(assertStartupContract(source).contractPassed,true);
  assert.throws(()=>assertStartupContract('require("fs")'),/Unexpected module/);
});
test('static inspection refuses output directories inside release artifact',t=>{
  const {actual}=release(t);
  assert.throws(()=>inspectUnpackedRelease(actual,{platform:'win32',config:DEFAULT_CONFIG,out:path.join(actual,'out')}),/OUTSIDE_ARTIFACT/);
});
test('CLI runs release compat and inspect with redacted report outputs',t=>{
  const {actual,root}=release(t);
  const project=path.join(root,'project');fs.mkdirSync(project);
  write(path.join(project,'package.json'),JSON.stringify({devDependencies:{electron:'33.4.11','@electron-forge/cli':'7.4.0'},config:{forge:{packagerConfig:{asar:true}}}}));
  const configFile=path.join(root,'fea.json'),planFile=path.join(root,'compat.json'),reports=path.join(root,'reports');
  write(configFile,JSON.stringify(DEFAULT_CONFIG));
  const cli=path.resolve('src/cli.mjs');
  let p=spawnSync(process.execPath,[cli,'release','compat',project,'--platform','win32','--out',planFile],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);
  p=spawnSync(process.execPath,[cli,'release','inspect',actual,'--platform','win32','--config',configFile,'--out',reports],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(reports,'release.json'),'utf8')).status,'static-checks-pass');
  assert.equal(fs.readFileSync(path.join(reports,'release.json'),'utf8').includes(actual),false);
});
