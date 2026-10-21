import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageInfo = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
const src = fs.readFileSync(path.join(root,'scripts','distribution-smoke.mjs'),'utf8');

test('release candidate has a public installable CLI with an explicit content allowlist',()=>{
  assert.equal(packageInfo.private,false);
  assert.equal(packageInfo.bin.fea,'./src/cli.mjs');
  assert.match(packageInfo.version,/^\d+\.\d+\.\d+-rc\.\d+$/);
  assert(Array.isArray(packageInfo.files));
  assert(packageInfo.files.includes('src/'));
  assert(packageInfo.files.includes('assets/fea-icon.png'));
  for(const excluded of ['demo/','test/','.github/'])assert(!packageInfo.files.includes(excluded));
  assert.deepEqual(packageInfo.dependencies??{},{});
});

test('offline package smoke never enables scripts or network package fetch',()=>{
  assert.match(src,/npm_config_offline:\s*'true'/);
  assert.match(src,/--ignore-scripts/);
  assert.match(src,/offlineInstall:\s*true/);
  assert.match(src,/npmBinShim:\s*true/);
  assert.match(src,/policyGate:\s*true/);
});

test('documentation distinguishes package smoke from publication signature or notarization',()=>{
  const docs=fs.readFileSync(path.join(root,'docs','PRODUCTION-READINESS.md'),'utf8');
  for(const phrase of ['Release criteria','Publisher verification','Unassessed','npm run distribution:smoke'])assert(docs.includes(phrase));
});
