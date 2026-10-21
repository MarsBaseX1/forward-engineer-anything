import fs from 'node:fs';
import path from 'node:path';

function readRegularJson(file) {
  if (!fs.existsSync(file)) return null;
  if (fs.lstatSync(file).isSymbolicLink() || !fs.statSync(file).isFile()) throw Error('Project config must be a regular file');
  const stat=fs.statSync(file);
  if(stat.size>1024*1024)throw Error('Project config exceeds 1 MiB');
  return JSON.parse(fs.readFileSync(file,'utf8'));
}
// Never evaluate forge.config.js, install packages or modify existing build files.
export function planForge(projectDir) {
  const root=path.resolve(projectDir);
  if(fs.lstatSync(root).isSymbolicLink() || !fs.statSync(root).isDirectory())throw Error('Expected regular project directory');
  const pkg=readRegularJson(path.join(root,'package.json'));
  if(!pkg || typeof pkg!=='object')throw Error('Expected package.json');
  const standalone=readRegularJson(path.join(root,'forge.config.json'));
  const embedded=pkg.config?.forge;
  const deps={...pkg.dependencies,...pkg.devDependencies};
  const forge=standalone ?? embedded;
  const hasForge=!!(forge && typeof forge==='object') || Object.keys(deps).some(k=>k.startsWith('@electron-forge/'));
  const source=standalone?'forge.config.json':embedded?'package.json#config.forge':fs.existsSync(path.join(root,'forge.config.js'))?'forge.config.js':'not found';
  const packagerConfig=forge?.packagerConfig;
  const asarValue=packagerConfig?.asar;
  const notes=[];
  if(!hasForge)notes.push('No supported Electron Forge manifest detected; no automatic changes are safe.');
  if(source==='forge.config.js')notes.push('JavaScript Forge configuration was NOT executed or parsed; settings unassessed.');
  if(asarValue!==true && !(asarValue&&typeof asarValue==='object'))notes.push('Review packagerConfig.asar=true with your packaging requirements. ASAR is not encryption.');
  else notes.push('ASAR packaging setting appears enabled in inspected JSON; confirm packaged result.');
  notes.push('Prevent .map and debug files from entering production resources; store diagnostic assets separately.');
  notes.push('For Electron Forge >=7.4.0 with supported Electron, review @electron-forge/plugin-fuses and enable EnableEmbeddedAsarIntegrityValidation + OnlyLoadAppFromAsar together. Test the complete packaged app.');
  notes.push('Rebuild, test functionality, sign/notarize, then verify FINAL packages; do not edit an already-signed executable.');
  return {
    formatVersion:1,kind:'electron-forge-review-plan',supported:hasForge,configSource:source,
    applied:false,configurationExecuted:false,notes,
    candidateConfig:{packagerConfig:{asar:true},fuses:{EnableEmbeddedAsarIntegrityValidation:true,OnlyLoadAppFromAsar:true}},
    notice:'Review-only suggestions, not a patch, hardened binary, signature verification or audited configuration. Only JSON manifests are inspected.'
  };
}
