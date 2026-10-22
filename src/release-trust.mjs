import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';

// Read-only evidence. A digest proves equality with an independently trusted value,
// NOT who published the bytes, and cannot replace signature verification.
const SHA = /^[a-f\d]{64}$/i;
const THUMB = /^[a-f\d]{40}$/i;
const TEAM = /^[A-Z0-9]{10}$/;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const bounded = (condition, code) => {if(!condition) throw Error(code);};
const MAX_FILES = 20_000, MAX_BYTES = 2_000_000_000, MAX_FILE = 600_000_000;

function regularRoot(target){
  const absolute=path.resolve(target),st=fs.lstatSync(absolute);
  bounded(!st.isSymbolicLink()&&(st.isFile()||st.isDirectory()),'TRUST_ROOT_UNSUPPORTED');
  if(st.isFile())bounded(st.nlink===1,'TRUST_HARDLINK_UNSUPPORTED');
  return {absolute,st};
}
function fileHash(filename,expected){
  const h=crypto.createHash('sha256');
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  try{
    const before=fs.fstatSync(fd);
    bounded(before.isFile()&&before.nlink===1&&before.size===expected.size&&before.size<=MAX_FILE,'TRUST_FILE_UNSUPPORTED');
    const buffer=Buffer.alloc(65536);
    for(let offset=0;offset<before.size;){
      const count=fs.readSync(fd,buffer,0,Math.min(buffer.length,before.size-offset),offset);
      bounded(count>0,'TRUST_SHORT_READ');h.update(buffer.subarray(0,count));offset+=count;
    }
    const after=fs.fstatSync(fd);
    bounded(after.size===before.size&&after.mtimeMs===before.mtimeMs&&after.ino===before.ino,'TRUST_INPUT_CHANGED');
    return h.digest('hex');
  }finally{fs.closeSync(fd);}
}

export function snapshotArtifact(target,{expectedSha256}={}){
  if(expectedSha256!==undefined)bounded(SHA.test(expectedSha256),'TRUST_EXPECTED_HASH_INVALID');
  const {absolute,st}=regularRoot(target);
  const files=[];let total=0;
  function walk(folder,relative,depth){
    bounded(depth<=40,'TRUST_DEPTH_LIMIT');
    const names=fs.readdirSync(folder,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
    for(const entry of names){
      bounded(entry.name!=='.'&&entry.name!=='..','TRUST_NAME_INVALID');
      const next=path.join(folder,entry.name),rel=relative?`${relative}/${entry.name}`:entry.name;
      const before=fs.lstatSync(next);
      bounded(!before.isSymbolicLink(),'TRUST_SYMLINK_UNSUPPORTED');
      if(before.isDirectory()){walk(next,rel,depth+1);continue;}
      bounded(before.isFile()&&before.nlink===1,'TRUST_NONREGULAR_UNSUPPORTED');
      add(next,rel,before);
    }
  }
  function add(filename,relative,stat){
    bounded(files.length<MAX_FILES,'TRUST_FILE_COUNT_LIMIT');
    total+=stat.size;
    bounded(total<=MAX_BYTES&&stat.size<=MAX_FILE,'TRUST_BYTE_LIMIT');
    files.push({pathId:sha(relative).slice(0,20),size:stat.size,sha256:fileHash(filename,stat)});
  }
  if(st.isFile())add(absolute,'.',st);else walk(absolute,'',0);
  bounded(files.length>0,'TRUST_EMPTY_ARTIFACT');
  const snapshotSha256=st.isFile()?files[0].sha256:sha(files.map(f=>`${f.pathId}:${f.size}:${f.sha256}\n`).join(''));
  const pinned=expectedSha256!==undefined;
  return {formatVersion:1,kind:'fea-release-evidence-manifest',inputKind:st.isFile()?'opaque-file':'directory',
    files:files.length,totalBytes:total,snapshotSha256,
    expectedDigestPinned:pinned,digestMatch:pinned?snapshotSha256===expectedSha256.toLowerCase():null,
    entries:files,coverage:{complete:true,symlinksAllowed:false},
    notice:'For a single file, snapshotSha256 is the raw file SHA-256; for a directory, it is a deterministic tree-manifest hash. Paths are SHA-256-derived IDs. Hashes are not signed attestations; no installer payload was extracted or verified.'};
}

export function assessWindowsOutput(payload,expectedThumbprint){
  bounded(THUMB.test(expectedThumbprint??''),'TRUST_WINDOWS_SIGNER_PIN_REQUIRED');
  const observed=typeof payload?.thumbprint==='string'?payload.thumbprint.replace(/\s/g,'').toUpperCase():'';
  const status=String(payload?.status??'Unassessed');
  const passed=status==='Valid'&&observed===expectedThumbprint.toUpperCase();
  return {status:passed?'verified':status==='Unassessed'?'unassessed':'rejected',passed,
    checks:{osSignatureValid:status==='Valid',expectedSignerMatched:observed===expectedThumbprint.toUpperCase()},
    signatureStatus:['Valid','NotSigned','UnknownError','HashMismatch','NotTrusted','NotTimeValid','Unassessed'].includes(status)?status:'other',
    notice:'Windows OS Authenticode status with a pinned signer certificate. SmartScreen reputation and complete installer contents remain unassessed.'};
}

export function assessMacOutputs(outputs,expectedTeamId,{requireNotarization=true}={}) {
  bounded(TEAM.test(expectedTeamId??''),'TRUST_MAC_TEAM_PIN_REQUIRED');
  const details=String(outputs?.details??'');
  const teamId=/^TeamIdentifier=(\S+)\s*$/m.exec(details)?.[1] ??
    /Developer ID (?:Installer|Application):[^\n]*\(([A-Z0-9]{10})\)/.exec(details)?.[1];
  const teamMatch=teamId===expectedTeamId;
  const signatureOk=outputs?.codesign===true;
  const gatekeeperOk=outputs?.gatekeeper===true;
  const ticketOk=outputs?.stapled===true;
  const passed=signatureOk&&teamMatch&&gatekeeperOk&&(!requireNotarization||ticketOk);
  return {status:passed?'verified':'rejected',passed,
    checks:{codeSignatureValid:signatureOk,expectedTeamMatched:teamMatch,gatekeeperAccepted:gatekeeperOk,
      stapledTicketValid:ticketOk},
    notice:requireNotarization?'macOS signed artifact with pinned Team ID, Gatekeeper assessment and stapled notarization ticket check. No notary service submission is performed.':'macOS signed artifact with pinned Team ID and Gatekeeper assessment; notarization ticket NOT required by this policy.'};
}

// Runner injection is for unit tests; CLI calls only system binaries on the native host.
export function verifyPublisher(target,{platform=process.platform,expectedThumbprint,expectedTeamId,requireNotarization=true}={},runner=spawnSync){
  const {absolute,st}=regularRoot(target);
  bounded(['win32','darwin'].includes(platform),'TRUST_PLATFORM_UNSUPPORTED');
  const base={formatVersion:1,kind:'fea-native-publisher-verification',platform,status:'unassessed',passed:false,
    unassessed:['installer-inner-files','updates','malware','smartscreen-reputation'],
    notice:'Publisher identity not verified. Never interpret this as a successful security check.'};
  if(platform!==process.platform)return {...base,notice:'Native OS verifier required. Different-host check is unassessed.'};
  if(platform==='win32') {
    const extension=path.extname(absolute).toLowerCase();
    bounded(st.isFile()&&['.exe','.msi'].includes(extension),'TRUST_WINDOWS_SIGNED_INSTALLER_REQUIRED');
    if(!expectedThumbprint)return {...base,notice:'Expected signer thumbprint is required for a trusted result.'};
    bounded(THUMB.test(expectedThumbprint),'TRUST_WINDOWS_SIGNER_PIN_INVALID');
    const ps="$ErrorActionPreference='Stop'; try { $r = [Console]::In.ReadToEnd() | ConvertFrom-Json; $s=Get-AuthenticodeSignature -LiteralPath $r.path; [pscustomobject]@{status=[string]$s.Status;thumbprint=[string]$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress } catch { [pscustomobject]@{status='Unassessed';thumbprint=''} | ConvertTo-Json -Compress; exit 2 }";
    const result=runner('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(ps,'utf16le').toString('base64')],
      {input:JSON.stringify({path:absolute}),encoding:'utf8',timeout:30000,maxBuffer:65536,windowsHide:true});
    if(result.error||result.status!==0)return {...base,notice:'Windows OS signature verification unavailable, failed, or timed out.'};
    let payload;try{payload=JSON.parse(result.stdout.trim());}catch{return {...base,notice:'Malformed Windows signature verification output.'};}
    return {...base,...assessWindowsOutput(payload,expectedThumbprint)};
  }
  const extension=path.extname(absolute).toLowerCase();
  const isApp=st.isDirectory()&&extension==='.app';
  const isDmg=st.isFile()&&extension==='.dmg';
  const isPkg=st.isFile()&&extension==='.pkg';
  bounded(isApp||isDmg||isPkg,'TRUST_MAC_SIGNED_ARTIFACT_REQUIRED');
  if(!expectedTeamId)return {...base,notice:'Expected Apple Team ID is required for a trusted result.'};
  bounded(TEAM.test(expectedTeamId),'TRUST_MAC_TEAM_PIN_INVALID');
  const exec=(tool,args)=>runner(tool,args,{encoding:'utf8',timeout:30000,maxBuffer:65536});
  let verify,details,gate;
  if(isApp) {
    verify=exec('codesign',['--verify','--deep','--strict',absolute]);
    details=exec('codesign',['--display','--verbose=4',absolute]);
    gate=exec('spctl',['--assess','--type','execute','--verbose=4',absolute]);
  } else if(isDmg) {
    verify=exec('codesign',['--verify','--verbose=4',absolute]);
    details=exec('codesign',['--display','--verbose=4',absolute]);
    gate=exec('spctl',['--assess','--type','open','--context','context:primary-signature','--verbose=4',absolute]);
  } else {
    verify=exec('pkgutil',['--check-signature',absolute]);
    details=verify;
    gate=exec('spctl',['--assess','--type','install','--verbose=4',absolute]);
  }
  const ticket=requireNotarization?exec('xcrun',['stapler','validate',absolute]):null;
  const items=[verify,details,gate,...(ticket?[ticket]:[])];
  if(items.some(x=>x.error))return {...base,notice:'macOS system verifier unavailable or timed out; status unassessed.'};
  return {...base,...assessMacOutputs({codesign:verify.status===0,details:(details.stdout??'')+'\n'+(details.stderr??''),
    gatekeeper:gate.status===0,stapled:ticket?.status===0},expectedTeamId,{requireNotarization})};
}
