import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {fileURLToPath} from 'node:url';
import {DEFAULT_CONFIG} from '../src/core.mjs';
import {packDemoAsar} from './pack-asar.mjs';
import {evaluateFuseCompatibility,inspectUnpackedRelease} from '../src/release-readiness.mjs';

const base=path.dirname(fileURLToPath(import.meta.url));

const write=(name,content)=>{fs.mkdirSync(path.dirname(name),{recursive:true});fs.writeFileSync(name,content);};
export function assertStartupContract(source){
  let loaded=0,created=0,ready=0,secure=false,quit=0,quitListener;
  class BrowserWindow{
    constructor(options){created++;secure=options?.webPreferences?.sandbox===true&&options.webPreferences?.contextIsolation===true&&options.webPreferences?.nodeIntegration===false;}
    loadFile(file){assert.equal(file,'index.html');loaded++;}
  }
  const electron={BrowserWindow,app:{whenReady:()=>({then(f){ready++;f();}}),on(name,cb){if(name==='window-all-closed')quitListener=cb;},quit(){quit++;}}};
  vm.runInNewContext(source,{require:name=>{if(name!=='electron')throw Error('Unexpected module');return electron;},process:{platform:'win32'}},{timeout:1000});
  assert.equal(ready,1);assert.equal(created,1);assert.equal(loaded,1);assert.equal(secure,true);
  quitListener();assert.equal(quit,1);
  return {contractPassed:true,realGuiExecuted:false};
}
export function runDemo(){
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'fea-release-v041-'));
  try{
  const project=path.join(temp,'project');fs.mkdirSync(project);
  write(path.join(project,'package.json'),JSON.stringify({devDependencies:{electron:'33.4.11','@electron-forge/cli':'7.4.0'},config:{forge:{packagerConfig:{asar:true}}}}));
  assert.equal(evaluateFuseCompatibility(project,'win32').status,'compatible-declarations');
  const unpacked=path.join(temp,'win-unpacked');fs.mkdirSync(unpacked);
  const pe=Buffer.alloc(256);pe.write('MZ');pe.writeUInt32LE(128,0x3c);pe.write('PE\0\0',128,'binary');
  write(path.join(unpacked,'demo.exe'),pe);
  packDemoAsar(path.join(base,'generated/hardened/app'),path.join(unpacked,'resources/app.asar'));
  const {result}=inspectUnpackedRelease(unpacked,{platform:'win32',config:DEFAULT_CONFIG});
  assert.equal(result.status,'static-checks-pass',JSON.stringify(result));
  const entry=fs.readFileSync(path.join(base,'electron-app/main.cjs'),'utf8');
  assertStartupContract(entry);
  write(path.join(temp,'release-report.json'),JSON.stringify(result,null,2));
  console.log('RELEASE READINESS DEMO PASS: version declarations, unpacked PE/ASAR static checks, and isolated Electron startup contract.');
  console.log('No actual Electron build, real GUI, binary fuses or signed integrity linkage was tested.');
  }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1] && fileURLToPath(import.meta.url)===path.resolve(process.argv[1]))runDemo();
