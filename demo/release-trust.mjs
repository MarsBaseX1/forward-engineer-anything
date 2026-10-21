import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {snapshotArtifact,verifyPublisher} from '../src/release-trust.mjs';
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'fea-release-trust-demo-'));
try {
  const out=path.join(tmp,'release.exe');fs.writeFileSync(out,Buffer.from('MZ: unsigned demo only'));
  const first=snapshotArtifact(out);
  if(!snapshotArtifact(out,{expectedSha256:first.snapshotSha256}).digestMatch)throw Error('GOOD_DIGEST_NOT_ACCEPTED');
  fs.appendFileSync(out,'-modified');
  if(snapshotArtifact(out,{expectedSha256:first.snapshotSha256}).digestMatch)throw Error('MODIFIED_DIGEST_ACCEPTED');
  // Only unsigned, owned fixture checked; no certificate or Apple Developer secret is required.
  const result=verifyPublisher(out,{platform:'win32',expectedThumbprint:'A'.repeat(40)});
  if(result.passed)throw Error('UNSIGNED_DEMO_TRUSTED');
  console.log('RELEASE TRUST DEMO PASS: matched pinned digest, rejected mutation, unsigned publisher not trusted');
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
