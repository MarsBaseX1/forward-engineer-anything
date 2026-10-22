import fs from 'node:fs';
import path from 'node:path';
import {snapshotArtifact,verifyPublisher} from './release-trust.mjs';

// Read-only, bounded container recognition. This does NOT extract installer payloads.
const CFB=Buffer.from('d0cf11e0a1b11ae1','hex');
const SHA=/^[0-9a-f]{64}$/i;
const kinds={'.exe':'windows-pe','.msi':'windows-msi-cfb','.dmg':'apple-udif-dmg','.pkg':'apple-xar-pkg'};
function regular(file){
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)throw Error('RELEASE_AUDIT_REGULAR_FILE_REQUIRED');
  if(st.size<1||st.size>600000000)throw Error('RELEASE_AUDIT_FILE_SIZE_UNSUPPORTED');
  return st;
}
function at(fd,offset,length){
  const b=Buffer.alloc(length);
  return b.subarray(0,fs.readSync(fd,b,0,length,offset));
}
export function recognizeInstaller(file){
  const st=regular(file),ext=path.extname(file).toLowerCase(),kind=kinds[ext];
  if(!kind)return {status:'unassessed',kind:'unsupported-extension',recognized:false,contentsInspected:false,notice:'Unsupported extension; installer contents not evaluated.'};
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  let found=false;
  try{
    const b=at(fd,0,Math.min(st.size,4096));
    if(ext==='.exe'&&b.length>=64&&b.toString('ascii',0,2)==='MZ'){
      const offset=b.readUInt32LE(0x3c);
      if(offset>=64&&offset<=st.size-24&&offset<1048576){
        const sig=offset+4<=b.length?b.subarray(offset,offset+4):at(fd,offset,4);
        found=sig.equals(Buffer.from('PE\0\0','binary'));
      }
    }else if(ext==='.msi'){
      found=b.length>=512&&b.subarray(0,8).equals(CFB)&&b.readUInt16LE(28)===65534&&[9,12].includes(b.readUInt16LE(30))&&b.readUInt16LE(32)===6;
    }else if(ext==='.dmg'){
      const tail=st.size>=512?at(fd,st.size-512,512):Buffer.alloc(0);
      found=tail.length===512&&tail.toString('ascii',0,4)==='koly'&&tail.readUInt32BE(4)===4&&tail.readUInt32BE(8)===512;
    }else if(ext==='.pkg'){
      found=b.length>=28&&b.toString('ascii',0,4)==='xar!'&&b.readUInt16BE(4)>=28&&b.readUInt16BE(4)<=st.size&&b.readUInt16BE(6)===1&&b.readBigUInt64BE(8)>0n&&b.readBigUInt64BE(8)<=BigInt(st.size-b.readUInt16BE(4));
    }
  }finally{fs.closeSync(fd);}
  return {status:found?'pass':'fail',kind,recognized:found,contentsInspected:false,
    notice:found?'Basic file magic and header invariants recognized; embedded payload and installer actions NOT checked.':'Magic/header mismatch or unsupported layout.'};
}
export function summarizeScanEvidence(r){
  if(!r||r.formatVersion!==1||!r.coverage||typeof r.coverage.complete!=='boolean'||!Array.isArray(r.coverage.errors)||!Array.isArray(r.findings)||r.findings.length>20000)throw Error('RELEASE_AUDIT_SCAN_EVIDENCE_INVALID');
  const failed=!r.coverage.complete||r.coverage.errors.length>0||r.findings.length>0;
  return {status:failed?'fail':'unassessed',findings:r.findings.length,coverageComplete:r.coverage.complete,provenance:'external-unverified-json',
    notice:'Imported reports are not authenticated. A clean self-reported scan remains unassessed.'};
}
export function summarizeNativeEvidence(r){
  if(!r||r.formatVersion!==1||r.kind!=='native-electron-forge-package-evidence'||!['win32','darwin'].includes(r.platform)||!r.checks)throw Error('RELEASE_AUDIT_NATIVE_EVIDENCE_INVALID');
  const keys=['fuses','embeddedAsarHeaderHash','guiSmoke'];
  if(keys.some(k=>typeof r.checks[k]!=='boolean'))throw Error('RELEASE_AUDIT_NATIVE_EVIDENCE_INVALID');
  return {status:keys.some(k=>!r.checks[k])?'fail':'unassessed',platform:r.platform,
    checks:Object.fromEntries(keys.map(k=>[k,r.checks[k]])),provenance:'external-unverified-json',
    notice:'Native-build report is self-reported, not independently attested.'};
}
function load(file){
  const st=regular(file);
  if(st.size>1048576)throw Error('RELEASE_AUDIT_EVIDENCE_TOO_LARGE');
  return JSON.parse(fs.readFileSync(file,'utf8'));
}
export function auditRelease(file,opts={}){
  const format=recognizeInstaller(file),snap=snapshotArtifact(file,{expectedSha256:opts.expectedSha256});
  const integrity={status:!snap.expectedDigestPinned?'unassessed':snap.digestMatch?'pass':'fail',
    expectedDigestPinned:snap.expectedDigestPinned,digestMatch:snap.digestMatch,
    notice:'Expected digest must originate from a separately trusted release source.'};
  let publisher={status:'unassessed',notice:'Publisher verification unavailable or not requested for this artifact.'};
  if(['windows-pe','windows-msi-cfb'].includes(format.kind)&&opts.publisher!==false){
    const r=verifyPublisher(file,{platform:'win32',expectedThumbprint:opts.expectedThumbprint});
    publisher={status:r.passed?'pass':r.status==='rejected'?'fail':'unassessed',nativeOsAssessed:r.status!=='unassessed',
      expectedSignerConfigured:!!opts.expectedThumbprint,notice:'Windows Authenticode requires a native Windows host and pinned signer certificate; both PE EXE and MSI are checked.'};
  } else if(['apple-udif-dmg','apple-xar-pkg'].includes(format.kind)&&opts.publisher!==false){
    const r=verifyPublisher(file,{platform:'darwin',expectedTeamId:opts.expectedTeamId,requireNotarization:true});
    publisher={status:r.passed?'pass':r.status==='rejected'?'fail':'unassessed',nativeOsAssessed:r.status!=='unassessed',
      expectedSignerConfigured:!!opts.expectedTeamId,notice:'Apple signature, pinned Team ID, Gatekeeper assessment and stapled notarization ticket require a native macOS host.'};
  }
  const scan=opts.scanEvidence===undefined?{status:'unassessed',notice:'No trusted release-resource scan attached.'}:summarizeScanEvidence(opts.scanEvidence);
  const native=opts.nativeEvidence===undefined?{status:'unassessed',notice:'No native fuse/GUI evidence attached.'}:summarizeNativeEvidence(opts.nativeEvidence);
  const checks={format,integrity,publisher,scan,native};
  const states=Object.values(checks).map(x=>x.status);
  const result=states.includes('fail')?'fail':states.includes('unassessed')?'unassessed':'pass';
  return {formatVersion:1,kind:'fea-unified-release-audit',result,checks,
    manifest:{files:snap.files,totalBytes:snap.totalBytes,snapshotSha256:snap.snapshotSha256},
    limitations:['no-installer-extraction','no-msi-dmg-pkg-signature-chain','no-independent-evidence-authentication','no-reverse-engineering-guarantee'],
    notice:'Experimental read-only gate. A clean imported report cannot establish verified security.'};
}
export function runAuditFromFiles(file,{expectedSha256,expectedThumbprint,expectedTeamId,scanReport,nativeReport}={}){
  if(expectedSha256!==undefined&&!SHA.test(expectedSha256))throw Error('RELEASE_AUDIT_SHA256_PIN_INVALID');
  return auditRelease(file,{expectedSha256,expectedThumbprint,expectedTeamId,
    scanEvidence:scanReport?load(scanReport):undefined,nativeEvidence:nativeReport?load(nativeReport):undefined});
}
export function auditMarkdown(r){
  const lines=['# FEA Unified Release Audit','','**Overall: '+r.result.toUpperCase()+'**','','| Check | Result |','| --- | --- |'];
  for(const [key,val] of Object.entries(r.checks))lines.push('| '+key+' | '+val.status+' |');
  lines.push('','Snapshot SHA-256: '+r.manifest.snapshotSha256,'','> No installer payload extraction, evidence attestation or anti-reverse-engineering guarantee.','');
  return lines.join('\n');
}
export const exitCodeForAudit=r=>r.result==='pass'?0:r.result==='fail'||r.result==='unassessed'?2:1;
