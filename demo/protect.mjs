import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {previewHardening,applyHardening,rollbackHardening} from '../src/protect-apply.mjs';
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'fea-v04-demo-'));
try{
  const project=path.join(dir,'owned-electron-fixture');fs.mkdirSync(project);
  const file=path.join(project,'package.json');
  fs.writeFileSync(file,JSON.stringify({name:'owned-demo',devDependencies:{
      '@electron-forge/cli':'^7.4.0','@electron-forge/plugin-fuses':'^7.4.0'},
    config:{forge:{packagerConfig:{asar:false,icon:'demo-icon'},plugins:[]}}},null,2)+'\n');
  const before=fs.readFileSync(file);const plan=previewHardening(project);
  assert.equal(plan.changeRequired,true);
  const result=applyHardening(project,plan,path.join(dir,'external-state'));
  assert.equal(JSON.parse(fs.readFileSync(file)).config.forge.packagerConfig.asar,true);
  rollbackHardening(project,result.receipt);
  assert.deepEqual(fs.readFileSync(file),before);
  console.log('PROTECT DEMO PASS: preview -> controlled apply -> byte-identical rollback.');
  console.log('This changed JSON configuration only; no release was built, signed or proved resistant to reverse engineering.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
