import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';

const SHA=/^[a-f0-9]{64}$/;
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const ASSERT=(condition,code)=>{if(!condition)throw Error(code);};
const FUSE_ENABLED=0x31;
const FUSE_DISABLED=0x30;
const EXPECTED={runAsNode:false,nodeOptions:false,cliInspect:false,asarIntegrity:true,onlyAsar:true};

export function validateFuseStates(config,{FuseV1Options:keys}){
  ASSERT(config && String(config.version)==='1','REAL_FUSE_VERSION_UNSUPPORTED');
  const mapping={runAsNode:keys.RunAsNode,nodeOptions:keys.EnableNodeOptionsEnvironmentVariable,
    cliInspect:keys.EnableNodeCliInspectArguments,asarIntegrity:keys.EnableEmbeddedAsarIntegrityValidation,
    onlyAsar:keys.OnlyLoadAppFromAsar};
  const observed={};
  for(const [key,index] of Object.entries(mapping)){
    ASSERT(Number.isSafeInteger(index),'REAL_FUSE_LIBRARY_UNSUPPORTED');
    const value=config[index];
    observed[key]=value===FUSE_ENABLED ? true:value===FUSE_DISABLED?false:null;
  }
  return {ok:Object.keys(EXPECTED).every(key=>observed[key]===EXPECTED[key]),expected:EXPECTED,observed};
}

export function verifyHeaderIntegrity({headerSha256,embeddedRecords,platform}){
  ASSERT(SHA.test(headerSha256),'REAL_HEADER_HASH_INVALID');
  ASSERT(['win32','darwin'].includes(platform),'REAL_PLATFORM_INVALID');
  const expectedKey=platform==='win32'?'resources\\app.asar':'Resources/app.asar';
  const records=platform==='win32'?embeddedRecords:[embeddedRecords];
  ASSERT(Array.isArray(records),'REAL_INTEGRITY_MISSING');
  const matching=records.filter(row=>row&&row.file===expectedKey);
  ASSERT(matching.length===1,'REAL_INTEGRITY_MISSING_OR_DUPLICATE');
  const row=matching[0];
  const alg=String(row.alg??row.algorithm??'').toLowerCase();
  const value=row.value??row.hash;
  ASSERT(alg==='sha256'&&typeof value==='string'&&SHA.test(value.toLowerCase()),'REAL_INTEGRITY_METADATA_INVALID');
  return {ok:value.toLowerCase()===headerSha256,headerSha256,embeddedSha256:value.toLowerCase()};
}

export function validateSmokeResult(report,expectedPlatform){
  ASSERT(report && report.formatVersion===1 && report.ok===true && report.marker==='FEA_PACKAGED_GUI_OK' &&
    report.reason==='page-loaded'&&report.platform===expectedPlatform,'REAL_GUI_SMOKE_FAILED');
  return {ok:true,platform:expectedPlatform,markerObserved:true};
}

// Discover only the CI-owned fixture's exact expected executable and archive.
// Avoid recursive traversal of untrusted paths or guesswork about file types.
export function locateFixture(outDir,platform){
  ASSERT(['win32','darwin'].includes(platform),'REAL_PLATFORM_INVALID');
  const st=fs.lstatSync(outDir);
  ASSERT(st.isDirectory()&&!st.isSymbolicLink(),'REAL_OUTPUT_UNSUPPORTED');
  const matches=[];
  for(const item of fs.readdirSync(outDir,{withFileTypes:true})){
    if(!item.isDirectory()||item.isSymbolicLink())continue;
    const folder=path.join(outDir,item.name);
    const app=platform==='darwin'?path.join(folder,'FEAElectronSmoke.app'):folder;
    const binary=platform==='darwin'?path.join(app,'Contents','MacOS','FEAElectronSmoke'):path.join(app,'FEAElectronSmoke.exe');
    const archive=platform==='darwin'?path.join(app,'Contents','Resources','app.asar'):path.join(app,'resources','app.asar');
    const infoPlist=platform==='darwin'?path.join(app,'Contents','Info.plist'):null;
    if([binary,archive,...(infoPlist?[infoPlist]:[])].every(f=>{
      try{const s=fs.lstatSync(f);return s.isFile()&&!s.isSymbolicLink();}catch{return false;}
    }))matches.push({app,binary,archive,infoPlist});
  }
  ASSERT(matches.length===1,'REAL_ARTIFACT_NOT_UNIQUE');
  return matches[0];
}

function embeddedIntegrity({platform,binary,infoPlist},deps){
  if(platform==='darwin'){
    const r=spawnSync('plutil',['-convert','json','-o','-',infoPlist],{encoding:'utf8',maxBuffer:1024*1024,timeout:15000});
    ASSERT(!r.error&&r.status===0,'REAL_PLIST_UNASSESSED');
    const payload=JSON.parse(r.stdout);
    const map=payload.ElectronAsarIntegrity;
    ASSERT(map&&typeof map==='object','REAL_PLIST_INTEGRITY_MISSING');
    const entry=map['Resources/app.asar'];
    return {file:'Resources/app.asar',algorithm:entry?.algorithm,hash:entry?.hash};
  }
  const st=fs.statSync(binary);
  ASSERT(st.size<=350*1024*1024,'REAL_PE_FILE_TOO_LARGE');
  const exe=deps.resedit.NtExecutable.from(fs.readFileSync(binary));
  const entries=deps.resedit.NtExecutableResource.from(exe).entries;
  const matches=entries.filter(e=>String(e.type).toUpperCase()==='INTEGRITY'&&String(e.id).toUpperCase()==='ELECTRONASAR');
  ASSERT(matches.length===1,'REAL_PE_INTEGRITY_RESOURCE_MISSING');
  const value=Buffer.from(matches[0].bin).toString('utf8').replace(/\0+$/,'');
  return JSON.parse(value);
}

function safeModules(fixtureDir){
  const req=createRequire(path.join(fixtureDir,'package.json'));
  return {fuses:req('@electron/fuses'),asar:req('@electron/asar'),resedit:req('resedit')};
}

function runGui(binary,platform,outDir){
  fs.mkdirSync(outDir,{recursive:true});
  const resultFile=path.join(outDir,'real-electron-smoke.json');
  ASSERT(!fs.existsSync(resultFile),'REAL_SMOKE_RESULT_ALREADY_EXISTS');
  const run=spawnSync(binary,['--fea-smoke'],{
    env:{...process.env,FEA_SMOKE_REPORT:resultFile},cwd:path.dirname(binary),timeout:30000,
    encoding:'utf8',maxBuffer:512*1024,windowsHide:true
  });
  ASSERT(!run.error&&run.status===0,'REAL_ELECTRON_EXIT_FAILURE');
  ASSERT(fs.existsSync(resultFile),'REAL_SMOKE_REPORT_MISSING');
  const report=JSON.parse(fs.readFileSync(resultFile,'utf8'));
  return validateSmokeResult(report,platform);
}

export async function verifyPackagedFixture({outDir,fixtureDir,platform,reportDir,runSmoke=true}){
  ASSERT(platform===process.platform,'REAL_NATIVE_HOST_REQUIRED');
  const {app,binary,archive,infoPlist}=locateFixture(outDir,platform);
  const deps=safeModules(fixtureDir);
  const wire=await deps.fuses.getCurrentFuseWire(platform==='darwin'?app:binary);
  const fuses=validateFuseStates(wire,deps.fuses);
  ASSERT(fuses.ok,'REAL_FUSE_MISMATCH');
  const raw=deps.asar.getRawHeader(archive);
  ASSERT(typeof raw.headerString==='string'&&raw.headerString.length>0,'REAL_ASAR_HEADER_INVALID');
  const headerSha256=sha(Buffer.from(raw.headerString,'utf8'));
  const metadata=embeddedIntegrity({platform,binary,infoPlist},deps);
  const integrity=verifyHeaderIntegrity({headerSha256,embeddedRecords:metadata,platform});
  ASSERT(integrity.ok,'REAL_EMBEDDED_HEADER_HASH_MISMATCH');
  const smoke=runSmoke?runGui(binary,platform,reportDir):{ok:false,unassessed:true};
  const report={formatVersion:1,kind:'native-electron-forge-package-evidence',platform,
    checks:{fuses:fuses.ok,embeddedAsarHeaderHash:integrity.ok,guiSmoke:smoke.ok},
    observedFuses:fuses.observed,asarHeaderSha256:integrity.headerSha256,
    unassessed:['code-signature-chain','notarization','installer-format','reverse-engineering-resistance'],
    notice:'Observed on an owned, unsigned Forge package. This is not code signing, a notarization assessment, or proof of security.'};
  fs.mkdirSync(reportDir,{recursive:true});
  fs.writeFileSync(path.join(reportDir,'real-package.json'),JSON.stringify(report,null,2)+'\n');
  return report;
}
