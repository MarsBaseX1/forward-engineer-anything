import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {snapshotArtifact} from '../src/release-trust.mjs';
import {auditRelease} from '../src/release-audit.mjs';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'fea-release-audit-demo-'));
try{
  const exe=path.join(root,'OwnedDemo.exe'),data=Buffer.alloc(160);
  data.write('MZ');data.writeUInt32LE(80,0x3c);data.write('PE\0\0',80,'binary');fs.writeFileSync(exe,data);
  const expected=snapshotArtifact(exe).snapshotSha256;
  const before=auditRelease(exe,{expectedSha256:expected});
  assert.equal(before.checks.format.status,'pass');
  assert.equal(before.checks.integrity.status,'pass');
  assert.notEqual(before.result,'pass','unsigned demonstration cannot be trusted');
  fs.appendFileSync(exe,'mutation');
  assert.equal(auditRelease(exe,{expectedSha256:expected}).result,'fail');
  console.log('RELEASE AUDIT DEMO PASS: format recognized, unsigned release unassessed, mutation rejected');
}finally{fs.rmSync(root,{recursive:true,force:true});}
