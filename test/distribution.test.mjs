import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {VERSION} from '../src/core.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageInfo = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
const src = fs.readFileSync(path.join(root,'scripts','distribution-smoke.mjs'),'utf8');

test('stable release has a public installable CLI with an explicit content allowlist',()=>{
  assert.equal(packageInfo.private,false);
  assert.equal(packageInfo.bin.fea,'./src/cli.mjs');
  assert.equal(packageInfo.version,'0.4.5');
  assert.equal(VERSION,packageInfo.version);
  assert.match(packageInfo.description,/Electron/i);
  assert.equal(packageInfo.repository.url,'git+https://github.com/MarsBaseX1/forward-engineer-anything.git');
  assert.equal(packageInfo.homepage,'https://github.com/MarsBaseX1/forward-engineer-anything#readme');
  assert.equal(packageInfo.bugs.url,'https://github.com/MarsBaseX1/forward-engineer-anything/issues');
  assert(Array.isArray(packageInfo.files));
  assert(packageInfo.files.includes('src/'));
  assert(packageInfo.files.includes('docs/*.md'));
  assert(!packageInfo.files.includes('docs/'));
  assert(packageInfo.files.includes('assets/fea-icon.png'));
  assert(packageInfo.files.includes('CHANGELOG.md'));
  assert(packageInfo.files.includes('SECURITY.md'));
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
