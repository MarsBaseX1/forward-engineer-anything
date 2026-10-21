#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {runAuditFromFiles,auditMarkdown,exitCodeForAudit} from '../src/release-audit.mjs';
try{
  const allowed=new Set(['out','expected-sha256','thumbprint','scan-report','native-report']);
  const flags={},positional=[];
  const a=process.argv.slice(2);
  for(let i=0;i<a.length;i++){
    if(!a[i].startsWith('--')){positional.push(a[i]);continue;}
    const key=a[i].slice(2);
    if(!allowed.has(key)||Object.hasOwn(flags,key)||!a[i+1]||a[i+1].startsWith('--'))throw Error('RELEASE_AUDIT_INVALID_FLAG');
    flags[key]=a[++i];
  }
  if(positional.length!==1||!flags.out)throw Error('Usage: node scripts/release-audit.mjs <EXE|MSI|DMG|PKG> --out <dir> [--expected-sha256 PIN] [--thumbprint CERT] [--scan-report JSON] [--native-report JSON]');
  const out=path.resolve(flags.out);
  if(out===path.resolve(positional[0]))throw Error('RELEASE_AUDIT_OUTPUT_OVERLAPS_INPUT');
  const result=runAuditFromFiles(positional[0],{
    expectedSha256:flags['expected-sha256'],expectedThumbprint:flags.thumbprint,
    scanReport:flags['scan-report'],nativeReport:flags['native-report']
  });
  fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'release-audit.json'),JSON.stringify(result,null,2)+'\n');
  fs.writeFileSync(path.join(out,'release-audit.md'),auditMarkdown(result));
  console.log('FEA release audit: '+result.result+' ('+result.checks.format.kind+')');
  process.exitCode=exitCodeForAudit(result);
}catch(e){console.error('FEA release audit error: '+e.message);process.exitCode=1;}
