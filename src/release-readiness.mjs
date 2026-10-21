import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {scanAsar,parseUniqueJson} from './asar.mjs';
import {validateConfig,verifyReport} from './core.mjs';

const SHA=/^[a-f0-9]{64}$/;
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const versions=/^(\d+)\.(\d+)\.(\d+)$/;
const plain=x=>x!==null && typeof x==='object' && !Array.isArray(x);
const relNoLink=(root,relative,kind='file')=>{
  let here=root;
  for(const part of relative.split('/')){
    if(!part||part==='.'||part==='..')throw Error('RELEASE_UNSAFE_PATH');
    here=path.join(here,part);
    const stat=fs.lstatSync(here);
    if(stat.isSymbolicLink())throw Error('RELEASE_SYMLINK_UNSUPPORTED');
    if(here!==path.join(root,...relative.split('/')) && !stat.isDirectory())throw Error('RELEASE_PATH_NOT_DIRECTORY');
  }
  const st=fs.lstatSync(here);
  if(kind==='file' && (!st.isFile()||st.nlink!==1))throw Error('RELEASE_FILE_UNSUPPORTED');
  if(kind==='dir' && !st.isDirectory())throw Error('RELEASE_DIRECTORY_UNSUPPORTED');
  return {file:here,stat:st};
};
const readJson=(root,relative)=>{
  const {file,stat}=relNoLink(root,relative);
  if(stat.size>1_048_576)throw Error('RELEASE_CONFIG_TOO_LARGE');
  return parseUniqueJson(new TextDecoder('utf-8',{fatal:true}).decode(fs.readFileSync(file)));
};
function exactVersion(value){const m=typeof value==='string'&&versions.exec(value);return m?{major:+m[1],minor:+m[2],patch:+m[3]}:null;}
const atLeast=(v,major,minor=0,patch=0)=>v && (v.major>major||(v.major===major&&(v.minor>minor||(v.minor===minor&&v.patch>=patch))));

// This evaluates declared versions only, not actual binary fuse bits.
export function evaluateFuseCompatibility(project,platform){
  if(!['win32','darwin'].includes(platform))throw Error('FUSE_PLATFORM_UNSUPPORTED');
  const st=fs.lstatSync(project);
  if(!st.isDirectory()||st.isSymbolicLink())throw Error('FUSE_PROJECT_UNSAFE');
  const root=fs.realpathSync(project),pkg=readJson(root,'package.json');
  if(!plain(pkg))throw Error('FUSE_PACKAGE_INVALID');
  const dependencies={...pkg.dependencies,...pkg.devDependencies};
  const electron=exactVersion(dependencies.electron),forge=exactVersion(dependencies['@electron-forge/cli']);
  const configFile=fs.existsSync(path.join(root,'forge.config.json'))?'forge.config.json':null;
  const scripts=['forge.config.js','forge.config.cjs','forge.config.mjs','forge.config.ts'];
  const dynamic=scripts.some(name=>fs.existsSync(path.join(root,name)));
  const jsonForge=configFile?readJson(root,configFile):pkg.config?.forge;
  const unsupported=dynamic || !plain(jsonForge) || (configFile&&pkg.config?.forge!==undefined);
  const asar=plain(jsonForge?.packagerConfig)&& (jsonForge.packagerConfig.asar===true||plain(jsonForge.packagerConfig.asar));
  const checks={electronPinned:!!electron,forgePinned:!!forge,
    electronPlatformSupport:!!electron&&atLeast(electron,platform==='win32'?30:16),
    forgeAsarIntegritySupport:!!forge&&atLeast(forge,7,4),
    asarEnabled:!!asar,jsonConfigInspected:!unsupported};
  const blockers=[];
  if(!electron)blockers.push('ELECTRON_VERSION_UNPINNED_OR_MISSING');
  else if(!checks.electronPlatformSupport)blockers.push('ELECTRON_ASAR_INTEGRITY_UNSUPPORTED');
  if(!forge)blockers.push('FORGE_VERSION_UNPINNED_OR_MISSING');
  else if(!checks.forgeAsarIntegritySupport)blockers.push('FORGE_ASAR_INTEGRITY_UNSUPPORTED');
  if(unsupported)blockers.push('FORGE_CONFIG_UNASSESSED');
  if(!asar)blockers.push('ASAR_NOT_CONFIRMED_ENABLED');
  return {formatVersion:1,platform,status:blockers.length?'unassessed':'compatible-declarations',
    checks,blockers, declaredVersions:{electron:electron?`${electron.major}.${electron.minor}.${electron.patch}`:null,
      forge:forge?`${forge.major}.${forge.minor}.${forge.patch}`:null},
    fusedBinaryVerified:false,
    notice:'Checks declarations only. Actual packaged binary fuse bits and embedded signed ASAR header hash are NOT verified.'};
}

function headerKind(bytes,platform){
  if(platform==='win32'){
    if(bytes.length<64||bytes.toString('ascii',0,2)!=='MZ')return false;
    const pe=bytes.readUInt32LE(0x3c);
    return pe>=64&&pe<=bytes.length-4&&bytes.toString('ascii',pe,pe+4)==='PE\x00\x00';
  }
  return bytes.length>=4 && ['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca'].includes(bytes.subarray(0,4).toString('hex'));
}
const checksumFile=file=>{
  const st=fs.statSync(file);
  if(st.size>1024*1024*1024)throw Error('RELEASE_FILE_TOO_LARGE');
  const h=crypto.createHash('sha256');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  try{
    const buffer=Buffer.alloc(65536);
    for(let pos=0;pos<st.size;){const count=fs.readSync(fd,buffer,0,Math.min(buffer.length,st.size-pos),pos);if(!count)throw Error('RELEASE_TRUNCATED_FILE');h.update(buffer.subarray(0,count));pos+=count;}
    const after=fs.fstatSync(fd);
    if(after.size!==st.size||after.mtimeMs!==st.mtimeMs)throw Error('RELEASE_INPUT_CHANGED');
    return h.digest('hex');
  }finally{fs.closeSync(fd);}
};
export function inspectUnpackedRelease(folder,{platform,config,expectedAsarSha256,out}={}){
  if(!['win32','darwin'].includes(platform))throw Error('RELEASE_PLATFORM_UNSUPPORTED');
  validateConfig(config);
  if(expectedAsarSha256!==undefined&&!SHA.test(expectedAsarSha256))throw Error('RELEASE_INVALID_EXPECTED_DIGEST');
  const top=fs.lstatSync(folder);
  if(!top.isDirectory()||top.isSymbolicLink())throw Error('RELEASE_ROOT_UNSAFE');
  const root=fs.realpathSync(folder);
  if(out){
    const requested=path.resolve(out);
    let parent=requested;
    while(!fs.existsSync(parent)){
      const next=path.dirname(parent);
      if(next===parent)throw Error('RELEASE_OUTPUT_PATH_INVALID');
      parent=next;
    }
    const dest=path.resolve(fs.realpathSync(parent),path.relative(parent,requested));
    if(dest===root||dest.startsWith(root+path.sep))throw Error('RELEASE_REPORT_MUST_BE_OUTSIDE_ARTIFACT');
  }
  const relative=platform==='win32'?'resources/app.asar':'Contents/Resources/app.asar';
  const {file:asar}=relNoLink(root,relative);
  const base=platform==='win32'?root:path.join(root,'Contents','MacOS');
  if(platform==='darwin')relNoLink(root,'Contents/MacOS','dir');
  const executables=fs.readdirSync(base,{withFileTypes:true}).filter(e=>platform==='win32'?e.name.toLowerCase().endsWith('.exe'):!e.name.startsWith('.'));
  if(executables.length!==1)throw Error('RELEASE_EXECUTABLE_COUNT_UNSUPPORTED');
  const executable=executables[0].name;
  const binary=relNoLink(root,(platform==='win32'?executable:`Contents/MacOS/${executable}`));
  const fd=fs.openSync(binary.file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  let magic;
  try{magic=Buffer.alloc(Math.min(4096,binary.stat.size));fs.readSync(fd,magic,0,magic.length,0);}finally{fs.closeSync(fd);}
  const binaryFormatRecognized=headerKind(magic,platform);
  const asarHash=checksumFile(asar);
  const scan=scanAsar(asar,config,{out});
  const policy=verifyReport(scan,config);
  const issues=[];
  if(!binaryFormatRecognized)issues.push('EXECUTABLE_HEADER_UNRECOGNIZED');
  if(expectedAsarSha256!==undefined&&asarHash!==expectedAsarSha256)issues.push('ASAR_EXPECTED_DIGEST_MISMATCH');
  if(!scan.coverage.complete)issues.push('ASAR_SCAN_INCOMPLETE');
  if(!policy.ok)issues.push('ASAR_POLICY_FAILED');
  const result={formatVersion:1,kind:'unpacked-electron-static-release-verification',platform,
    status:issues.length?'fail':'static-checks-pass',issues,checks:{binaryFormatRecognized,
      asarDigestPinned:expectedAsarSha256!==undefined,
      asarDigestMatches:expectedAsarSha256===undefined?null:asarHash===expectedAsarSha256,
      asarScanComplete:scan.coverage.complete,policyAccepted:policy.ok},
    evidence:{asarSha256:asarHash,executableSha256:checksumFile(binary.file),
      asarScanDigest:scan.inputDigest,artifactType:'unpacked'},
    unassessed:['binary-fuse-bits','embedded-asar-header-hash','platform-code-signature','GUI-startup','installer-contents'],
    notice:'Static checks only; input must be a trusted, stable unpacked build. No binary was executed or signed. Hash is not independently authenticated.'};
  return {result,scan};
}
