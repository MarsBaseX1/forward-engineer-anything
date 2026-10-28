import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {VERSION} from '../src/core.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageInfo = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
const src = fs.readFileSync(path.join(root,'scripts','distribution-smoke.mjs'),'utf8');
const cli = fs.readFileSync(path.join(root,'src','cli.mjs'),'utf8');
const workflow = fs.readFileSync(path.join(root,'.github','workflows','fea-distribution.yml'),'utf8');
const releaseWorkflow = fs.readFileSync(path.join(root,'.github','workflows','fea-release-package.yml'),'utf8');

test('v1.0.1 has consistent public package metadata and an explicit content allowlist',()=>{
  assert.equal(packageInfo.private,false);
  assert.equal(packageInfo.bin.fea,'./src/cli.mjs');
  assert.equal(packageInfo.version,'1.0.1');
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
  assert(packageInfo.files.includes('CONTRIBUTING.md'));
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

test('documentation distinguishes package smoke from publication signature or notarization',()=>{
  const docs=fs.readFileSync(path.join(root,'docs','PRODUCTION-READINESS.md'),'utf8');
  for(const phrase of ['Release criteria','Publisher verification','Unassessed','npm run distribution:smoke'])assert(docs.includes(phrase));
});

test('CLI banner agrees with the stable package version and does not call itself experimental',()=>{
  assert.ok(cli.includes('Electron release-resource security checks (stable)'));
  assert.doesNotMatch(cli,/experimental/i);
});

test('distribution evidence is written to a visible artifact path',()=>{
  assert.ok(workflow.includes('FEA_DISTRIBUTION_REPORT: artifacts/fea-distribution-${{ runner.os }}.json'));
  assert.ok(workflow.includes('path: artifacts/fea-distribution-*.json'));
  assert.doesNotMatch(workflow,/path:\s*\.fea\/distribution-/);
});

test('release workflow creates only a draft after cross-platform and native checks',()=>{
  assert.ok(releaseWorkflow.includes('workflow_dispatch:'));
  assert.ok(releaseWorkflow.includes('os: [ubuntu-latest, windows-latest, macos-15-intel]'));
  assert.ok(releaseWorkflow.includes('needs: [verify, native-package]'));
  assert.ok(releaseWorkflow.includes('--draft'));
  assert.ok(releaseWorkflow.includes('SHA256SUMS.txt'));
  assert.ok(releaseWorkflow.includes('--target "$GITHUB_SHA"'));
  assert.ok(releaseWorkflow.includes("github.ref == 'refs/heads/main'"));
  assert.doesNotMatch(releaseWorkflow,/npm publish/i);
});
