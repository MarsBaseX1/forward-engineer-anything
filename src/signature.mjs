import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

// Uses Windows OS Authenticode validation; never signs or modifies the executable.
// No assumptions about revocation/network reachability or certificate ownership.
export function verifyAuthenticode(filename,{expectedThumbprint}={}) {
  const file=path.resolve(filename);
  if(!file.toLowerCase().endsWith('.exe'))throw Error('Only Windows PE .exe is supported');
  if(fs.lstatSync(file).isSymbolicLink()||!fs.statSync(file).isFile())throw Error('Expected regular EXE file');
  if(expectedThumbprint && !/^[a-f\d]{40}$/i.test(expectedThumbprint))throw Error('Expected SHA1 certificate thumbprint (40 hexadecimal characters)');
  const base={formatVersion:1,kind:'windows-authenticode',platform:process.platform,
    assessed:false,valid:false,status:'unassessed',publisherMatch:null,expectedPublisherConfigured:!!expectedThumbprint,
    notice:'Trust verification was not completed. Do not treat this as signed or safe.'};
  if(process.platform!=='win32')return {...base,notice:'Windows-only PowerShell Get-AuthenticodeSignature required; other platforms are unassessed.'};
  // Send path as JSON on stdin, so a malicious filename cannot be interpreted as PowerShell source.
  const command=`$ErrorActionPreference='Stop'; try { $r=[Console]::In.ReadToEnd() | ConvertFrom-Json; $s=Get-AuthenticodeSignature -LiteralPath $r.path; [pscustomobject]@{status=[string]$s.Status;thumbprint=[string]$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress } catch { [pscustomobject]@{status='Unassessed';thumbprint=''} | ConvertTo-Json -Compress; exit 2 }`;
  const encoded=Buffer.from(command,'utf16le').toString('base64');
  const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',encoded],{
    input:JSON.stringify({path:file}),encoding:'utf8',timeout:25000,maxBuffer:65536,windowsHide:true
  });
  if(result.error||result.status!==0)return {...base,notice:'PowerShell verification unavailable or failed; status is unassessed.'};
  let data;try{data=JSON.parse(result.stdout.trim());}catch{return {...base,notice:'Platform verification output could not be parsed.'};}
  const status=String(data.status||'Unassessed');
  const thumbprint=String(data.thumbprint||'').replace(/\s/g,'').toUpperCase();
  const publisherMatch=expectedThumbprint?thumbprint===expectedThumbprint.toUpperCase():null;
  const valid=status==='Valid' && publisherMatch!==false;
  return {...base,assessed:true,valid,status,publisherMatch,
    notice:valid?'Signature status Valid'+(expectedThumbprint?' and expected signer matched.':' (publisher identity not pinned).'):'Signature not valid, missing, or expected signer mismatch.'};
}
