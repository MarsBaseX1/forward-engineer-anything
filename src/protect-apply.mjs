import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseUniqueJson} from './asar.mjs';

// This experimental patcher only changes reviewed JSON build settings. It does NOT
// execute a project's JavaScript, run a build, change already-signed artifacts,
// install dependencies, or claim that ASAR encrypts client code.
const SHA=/^[0-9a-f]{64}$/;
const digest=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const plain=o=>o!==null && typeof o==='object' && !Array.isArray(o);
function regularFile(file){
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>1024*1024)throw Error('PROTECT_UNSAFE_FILE');
  return st;
}
function rootOf(project){
  const st=fs.lstatSync(project);
  if(!st.isDirectory()||st.isSymbolicLink())throw Error('PROTECT_PROJECT_DIRECTORY_REQUIRED');
  return fs.realpathSync(project);
}
function loadJson(file){
  regularFile(file);
  const bytes=fs.readFileSync(file);
  const value=parseUniqueJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  if(!plain(value))throw Error('PROTECT_JSON_OBJECT_REQUIRED');
  return {bytes,value};
}
function inside(root,location){return location===root||location.startsWith(root+path.sep);}
function checkForge(root){
  const pkg=loadJson(path.join(root,'package.json'));
  const deps={...pkg.value.dependencies,...pkg.value.devDependencies};
  const forgeVersion=deps['@electron-forge/cli'];
  const v=typeof forgeVersion==='string'?/^[~^]?7\.(\d+)\.(\d+)(?:$|[-+][a-zA-Z0-9.-]+$)/.exec(forgeVersion):null;
  if(!v||Number(v[1])<4)throw Error('PROTECT_FORGE_VERSION_UNSUPPORTED');
  if(['forge.config.js','forge.config.cjs','forge.config.mjs','forge.config.ts'].some(p=>fs.existsSync(path.join(root,p))))
    throw Error('PROTECT_EXECUTABLE_FORGE_CONFIG_UNSUPPORTED');
  const standalone=fs.existsSync(path.join(root,'forge.config.json'));
  const embedded=plain(pkg.value.config)&&Object.hasOwn(pkg.value.config,'forge');
  if(standalone&&embedded)throw Error('PROTECT_AMBIGUOUS_FORGE_CONFIG');
  if(!standalone&&!embedded)throw Error('PROTECT_JSON_FORGE_CONFIG_REQUIRED');
  const relative=standalone?'forge.config.json':'package.json';
  const chosen=standalone?loadJson(path.join(root,relative)):pkg;
  const forge=standalone?chosen.value:chosen.value.config?.forge;
  if(!plain(forge))throw Error('PROTECT_INVALID_FORGE_CONFIG');
  if(forge.packagerConfig!==undefined&&!plain(forge.packagerConfig))throw Error('PROTECT_PACKAGER_CONFIG_UNSUPPORTED');
  const currentAsar=forge.packagerConfig?.asar;
  if(currentAsar!==undefined && currentAsar!==false && currentAsar!==true && !plain(currentAsar))
    throw Error('PROTECT_ASAR_SETTING_UNSUPPORTED');
  const edited=JSON.parse(JSON.stringify(chosen.value));
  const editedForge=standalone?edited:edited.config.forge;
  editedForge.packagerConfig??={};
  const changes=[];
  if(currentAsar===undefined||currentAsar===false){
    editedForge.packagerConfig.asar=true;
    changes.push({operation:'set',setting:'packagerConfig.asar',value:true});
  }
  // Recommend and apply key Electron Fuses for ASAR integrity when the plugins array is plain JSON.
  const plugins=editedForge.plugins;
  const recommendedFuses={EnableEmbeddedAsarIntegrityValidation:true,OnlyLoadAppFromAsar:true};
  let fusePluginIndex=-1;
  if(Array.isArray(plugins)){
    fusePluginIndex=plugins.findIndex(p=>Array.isArray(p)&&p[0]==='@electron-forge/plugin-fuses');
  }
  if(fusePluginIndex===-1){
    editedForge.plugins??=[];
    editedForge.plugins.push(['@electron-forge/plugin-fuses',{version:1,fuses:recommendedFuses}]);
    changes.push({operation:'add',setting:'plugins.@electron-forge/plugin-fuses',value:recommendedFuses});
  } else {
    const existing=plugins[fusePluginIndex][1]||{};
    const existingFuses=existing.fuses||{};
    const updated={...existingFuses,...recommendedFuses};
    if(JSON.stringify(existingFuses)!==JSON.stringify(updated)){
      plugins[fusePluginIndex][1]={...existing,fuses:updated};
      changes.push({operation:'merge',setting:'plugins.@electron-forge/plugin-fuses.fuses',value:recommendedFuses});
    }
  }
  const original=chosen.bytes.toString('utf8');
  const indentation=/^\s+"[^"\n]+"\s*:/m.exec(original)?.[0].match(/^\s*/)?.[0]??'  ';
  const newline=original.includes('\r\n')?'\r\n':'\n';
  const hadNewline=/\r?\n$/.test(original);
  const rendered=JSON.stringify(edited,null,Math.min(8,Math.max(1,indentation.length)))
    .replace(/\n/g,newline)+(hadNewline?newline:'');
  const afterBytes=Buffer.from(rendered);
  const changed=changes.length>0;
  return {root,relative,beforeBytes:chosen.bytes,afterBytes:changed?afterBytes:chosen.bytes,
    changed,stat:regularFile(path.join(root,relative)),forgeVersion,changes};
}
export function previewHardening(project){
  const result=checkForge(rootOf(project));
  return {formatVersion:1,kind:'fea-forge-json-asar-fuses-v1',supported:true,
    configFile:result.relative,fromSha256:digest(result.beforeBytes),toSha256:digest(result.afterBytes),
    changeRequired:result.changed,changes:result.changes,
    notice:'Preview only. ASAR is packaging, not encryption. Fuses raise the cost of loading unpacked or modified resources. Review, rebuild, test, sign and verify FINAL artifacts.'};
}
function privateExternalState(root,state){
  if(typeof state!=='string'||!state.trim())throw Error('PROTECT_STATE_DIRECTORY_REQUIRED');
  const directory=path.resolve(state);
  if(inside(root,directory))throw Error('PROTECT_STATE_MUST_BE_OUTSIDE_PROJECT');
  let cursor=directory;
  while(true){
    try {if(fs.lstatSync(cursor).isSymbolicLink())throw Error('PROTECT_STATE_SYMLINK');}
    catch(error){if(error.code!=='ENOENT')throw error;}
    const parent=path.dirname(cursor);if(parent===cursor)break;cursor=parent;}
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  if(!fs.statSync(directory).isDirectory())throw Error('PROTECT_INVALID_STATE_DIRECTORY');
  return directory;
}
function atomicReplace(file,bytes,mode){
  const tmp=path.join(path.dirname(file),'.fea-'+crypto.randomUUID()+'.tmp');
  try{fs.writeFileSync(tmp,bytes,{flag:'wx',mode:mode&0o777});
    fs.chmodSync(tmp,mode&0o777);
    fs.renameSync(tmp,file);
  }finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}
}
export function applyHardening(project,plan,state){
  const root=rootOf(project),live=checkForge(root);
  const expected=previewHardening(root);
  if(!plain(plan)||plan.formatVersion!==1||plan.kind!==expected.kind||
    plan.configFile!==expected.configFile||plan.fromSha256!==expected.fromSha256||
    plan.toSha256!==expected.toSha256||plan.changeRequired!==expected.changeRequired||
    JSON.stringify(plan.changes)!==JSON.stringify(expected.changes))throw Error('PROTECT_PLAN_STALE_OR_INVALID');
  if(!live.changed)throw Error('PROTECT_ALREADY_CONFIGURED');
  const directory=privateExternalState(root,state);
  const session=path.join(directory,'fea-'+crypto.randomUUID());
  fs.mkdirSync(session,{mode:0o700});
  const backupFile=path.join(session,'original.bin');
  fs.writeFileSync(backupFile,live.beforeBytes,{flag:'wx',mode:0o600});
  const receipt={formatVersion:1,kind:'fea-forge-json-rollback-v1',
    projectRoot:root,configFile:live.relative,fromSha256:expected.fromSha256,toSha256:expected.toSha256,
    originalMode:live.stat.mode&0o777,rolledBack:false};
  fs.writeFileSync(path.join(session,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
  const target=path.join(root,live.relative);
  if(digest(fs.readFileSync(target))!==expected.fromSha256)throw Error('PROTECT_INPUT_CHANGED');
  atomicReplace(target,live.afterBytes,receipt.originalMode);
  return {changed:true,configFile:live.relative,receipt:path.join(session,'receipt.json'),
    before:expected.fromSha256,after:expected.toSha256,
    notice:'Config edit only (asar + recommended integrity fuses). Build, run regression tests, then sign and verify final artifacts.'};
}
export function rollbackHardening(project,receiptPath){
  const root=rootOf(project),receiptFile=path.resolve(receiptPath);
  if(inside(root,receiptFile))throw Error('PROTECT_RECEIPT_MUST_BE_OUTSIDE_PROJECT');
  const receipt=loadJson(receiptFile).value;
  if(receipt.formatVersion!==1||receipt.kind!=='fea-forge-json-rollback-v1'||
    receipt.projectRoot!==root||!['package.json','forge.config.json'].includes(receipt.configFile)||
    !SHA.test(receipt.fromSha256??'')||!SHA.test(receipt.toSha256??'')||
    !Number.isSafeInteger(receipt.originalMode)||receipt.rolledBack!==false)
      throw Error('PROTECT_RECEIPT_INVALID');
  const target=path.join(root,receipt.configFile);
  regularFile(target);
  const current=fs.readFileSync(target);
  if(digest(current)!==receipt.toSha256)throw Error('PROTECT_TARGET_CHANGED_REFUSE_ROLLBACK');
  const original=path.join(path.dirname(receiptFile),'original.bin');
  regularFile(original);
  const bytes=fs.readFileSync(original);
  if(digest(bytes)!==receipt.fromSha256)throw Error('PROTECT_BACKUP_HASH_MISMATCH');
  atomicReplace(target,bytes,receipt.originalMode);
  receipt.rolledBack=true;
  fs.writeFileSync(receiptFile,JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
  return {restored:true,configFile:receipt.configFile,sha256:receipt.fromSha256};
}
