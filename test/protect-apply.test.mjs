import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {previewHardening,applyHardening,rollbackHardening} from '../src/protect-apply.mjs';
const h=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t,standalone=false){
  const top=fs.mkdtempSync(path.join(os.tmpdir(),'fea-protect-v04-'));
  t.after(()=>fs.rmSync(top,{force:true,recursive:true}));
  const project=path.join(top,'project'),state=path.join(top,'state');fs.mkdirSync(project);
  const pkg={name:'owned-fixture',private:true,devDependencies:{
      '@electron-forge/cli':'^7.4.0','@electron-forge/plugin-fuses':'^7.4.0'},
    config:standalone?undefined:{forge:{packagerConfig:{asar:false,icon:'kept'},plugins:[]}}};
  fs.writeFileSync(path.join(project,'package.json'),JSON.stringify(pkg,null,2)+'\n');
  if(standalone)fs.writeFileSync(path.join(project,'forge.config.json'),JSON.stringify({packagerConfig:{asar:false,icon:'kept'}},null,2)+'\n');
  return {top,project,state,target:path.join(project,standalone?'forge.config.json':'package.json')};
}
test('preview is read-only, preserves original and avoids copying embedded tokens into plan',t=>{
  const {project,target}=fixture(t);
  const text=fs.readFileSync(target,'utf8').replace('"private": true,','"private": true,\n  "someSecret": "SYNTHETIC-SENSITIVE-EXAMPLE",');
  fs.writeFileSync(target,text);
  const preview=previewHardening(project);
  assert.equal(preview.changeRequired,true);assert.equal(preview.configFile,'package.json');
  assert.equal(preview.fromSha256,h(fs.readFileSync(target)));
  assert.equal(JSON.stringify(preview).includes('SYNTHETIC-SENSITIVE-EXAMPLE'),false);
  assert.equal(fs.readFileSync(target,'utf8'),text);
});
test('embedded Forge: apply and rollback restore identical bytes while preserving unrelated settings',t=>{
  const {project,state,target}=fixture(t);
  const original=fs.readFileSync(target),plan=previewHardening(project);
  const result=applyHardening(project,plan,state);
  assert.equal(result.changed,true);
  const updated=JSON.parse(fs.readFileSync(target,'utf8'));
  assert.equal(updated.config.forge.packagerConfig.asar,true);
  assert.equal(updated.config.forge.packagerConfig.icon,'kept');
  const fuses=updated.config.forge.plugins.find(p=>p.name==='@electron-forge/plugin-fuses');
  assert.deepEqual(fuses,{name:'@electron-forge/plugin-fuses',config:{version:'1','4':true,'5':true}});
  assert.equal(h(fs.readFileSync(target)),plan.toSha256);
  assert.equal(rollbackHardening(project,result.receipt).restored,true);
  assert.deepEqual(fs.readFileSync(target),original);
  assert.throws(()=>rollbackHardening(project,result.receipt),/RECEIPT_INVALID/);
});
test('standalone forge.config.json updates only allowed manifest',t=>{
  const {project,state,target}=fixture(t,true);
  const originalPkg=fs.readFileSync(path.join(project,'package.json'));
  const before=fs.readFileSync(target);
  const plan=previewHardening(project);assert.equal(plan.configFile,'forge.config.json');
  const receipt=applyHardening(project,plan,state).receipt;
  assert.equal(JSON.parse(fs.readFileSync(target)).packagerConfig.asar,true);
  assert.deepEqual(fs.readFileSync(path.join(project,'package.json')),originalPkg);
  rollbackHardening(project,receipt);
  assert.deepEqual(fs.readFileSync(target),before);
});
test('stale plan fails closed and cannot overwrite modifications',t=>{
  const {project,state,target}=fixture(t);const plan=previewHardening(project);
  fs.appendFileSync(target,'\n');const current=fs.readFileSync(target);
  assert.throws(()=>applyHardening(project,plan,state),/PLAN_STALE/);
  assert.deepEqual(fs.readFileSync(target),current);
});
test('tampered plan operations fail closed',t=>{
  const {project,state}=fixture(t);const plan=previewHardening(project);
  plan.changes[0].setting='scripts.postinstall';
  assert.throws(()=>applyHardening(project,plan,state),/PLAN_STALE/);
});
test('rollback refuses changes made after applying and retains backup',t=>{
  const {project,state,target}=fixture(t);const result=applyHardening(project,previewHardening(project),state);
  fs.appendFileSync(target,'\n');
  assert.throws(()=>rollbackHardening(project,result.receipt),/TARGET_CHANGED/);
  assert.equal(fs.existsSync(path.join(path.dirname(result.receipt),'original.bin')),true);
});
test('modified backup prevents rollback',t=>{
  const {project,state,target}=fixture(t);const result=applyHardening(project,previewHardening(project),state);
  const current=fs.readFileSync(target);
  fs.writeFileSync(path.join(path.dirname(result.receipt),'original.bin'),'tampered');
  assert.throws(()=>rollbackHardening(project,result.receipt),/BACKUP_HASH/);
  assert.deepEqual(fs.readFileSync(target),current);
});
test('state directory must be outside protected project',t=>{
  const {project}=fixture(t);
  assert.throws(()=>applyHardening(project,previewHardening(project),path.join(project,'.fea')),/STATE_MUST_BE_OUTSIDE/);
});
test('unsupported executable Forge JS config never runs',t=>{
  const {project,state,target}=fixture(t);
  fs.writeFileSync(path.join(project,'forge.config.js'),'throw Error("EXECUTED")');
  assert.throws(()=>previewHardening(project),/EXECUTABLE_FORGE_CONFIG/);
  assert.equal(JSON.parse(fs.readFileSync(target)).config.forge.packagerConfig.asar,false);
});
test('unsupported version and ambiguous sources fail closed',t=>{
  const {project,target}=fixture(t);
  let obj=JSON.parse(fs.readFileSync(target));obj.devDependencies['@electron-forge/cli']='6.5.0';
  fs.writeFileSync(target,JSON.stringify(obj));assert.throws(()=>previewHardening(project),/VERSION_UNSUPPORTED/);
  obj.devDependencies['@electron-forge/cli']='^7.4.0';fs.writeFileSync(target,JSON.stringify(obj));
  fs.writeFileSync(path.join(project,'forge.config.json'),'{}');
  assert.throws(()=>previewHardening(project),/AMBIGUOUS/);
});
test('missing Forge fuses plugin dependency fails before producing a plan',t=>{
  const {project,target}=fixture(t);const obj=JSON.parse(fs.readFileSync(target));
  delete obj.devDependencies['@electron-forge/plugin-fuses'];
  fs.writeFileSync(target,JSON.stringify(obj));
  assert.throws(()=>previewHardening(project),/FUSES_PLUGIN_REQUIRED/);
});
test('already fully configured ASAR and fuses yields no-op preview, refuse apply',t=>{
  const {project,state,target}=fixture(t);const obj=JSON.parse(fs.readFileSync(target));
  obj.config.forge.packagerConfig.asar=true;
  obj.config.forge.plugins=[{name:'@electron-forge/plugin-fuses',config:{version:'1','4':true,'5':true}}];
  fs.writeFileSync(target,JSON.stringify(obj));
  const plan=previewHardening(project);
  assert.equal(plan.changeRequired,false);
  assert.throws(()=>applyHardening(project,plan,state),/ALREADY_CONFIGURED/);
});
test('existing Forge fuses plugin keeps unrelated fuse choices while enabling integrity pair',t=>{
  const {project,target}=fixture(t);const obj=JSON.parse(fs.readFileSync(target));
  obj.config.forge.plugins=[{name:'@electron-forge/plugin-fuses',config:{version:'1','0':false,'4':false}}];
  fs.writeFileSync(target,JSON.stringify(obj));
  const plan=previewHardening(project);
  const changed=structuredClone(obj);
  changed.config.forge.packagerConfig.asar=true;
  changed.config.forge.plugins[0].config={'0':false,'4':true,'5':true,version:'1'};
  assert.equal(plan.changeRequired,true);
  applyHardening(project,plan,path.join(path.dirname(project),'state'));
  const result=JSON.parse(fs.readFileSync(target));
  assert.deepEqual(result.config.forge.plugins[0].config,changed.config.forge.plugins[0].config);
});
test('symlink config rejected; no edits to external content',t=>{
  const {project,top,target}=fixture(t);
  const ext=path.join(top,'external.json');fs.copyFileSync(target,ext);fs.unlinkSync(target);
  try{fs.symlinkSync(ext,target);}catch(e){if(['EPERM','EACCES'].includes(e.code))return;throw e;}
  assert.throws(()=>previewHardening(project),/UNSAFE_FILE/);
});
test('duplicate JSON keys cannot be silently normalized',t=>{
  const {project,target}=fixture(t);
  fs.writeFileSync(target,'{"config":{"forge":{}},"config":{"forge":{}}}');
  assert.throws(()=>previewHardening(project),/DUPLICATE/);
});
test('CLI preview/apply/rollback works end to end with explicit external backup',t=>{
  const {project,state,target}=fixture(t);
  const original=fs.readFileSync(target);
  const planFile=path.join(path.dirname(state),'plan.json');
  const cli=path.resolve('src/cli.mjs');
  const invoke=(args)=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8'});
  let result=invoke(['protect','preview',project,'--out',planFile]);
  assert.equal(result.status,0,result.stderr);
  result=invoke(['protect','apply',project,'--plan',planFile,'--state',state]);
  assert.equal(result.status,0,result.stderr);
  const r=fs.readdirSync(state).find(x=>x.startsWith('fea-'));
  result=invoke(['protect','rollback',project,'--receipt',path.join(state,r,'receipt.json')]);
  assert.equal(result.status,0,result.stderr);
  assert.deepEqual(fs.readFileSync(target),original);
});
