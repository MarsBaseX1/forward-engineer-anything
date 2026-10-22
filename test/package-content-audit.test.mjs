import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import {auditPackageTarball} from '../scripts/package-content-audit.mjs';

function header(name, size, type = '0', mode = 0o100644) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
  h.write('0000000\0', 108, 8, 'ascii');
  h.write('0000000\0', 116, 8, 'ascii');
  h.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  h.write('00000000000\0', 136, 12, 'ascii');
  h.fill(0x20, 148, 156);
  h[156] = type.charCodeAt(0);
  h.write('ustar\0', 257, 6, 'ascii');
  h.write('00', 263, 2, 'ascii');
  let sum = 0;
  for (const byte of h) sum += byte;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return h;
}
function makeTar(entries) {
  const blocks = [];
  for (const entry of entries) {
    const bytes = Buffer.isBuffer(entry.bytes) ? entry.bytes : Buffer.from(entry.bytes ?? '');
    blocks.push(header(entry.name, bytes.length, entry.type ?? '0', entry.mode ?? 0o100644));
    if (bytes.length) {
      blocks.push(bytes);
      const padding = (512 - (bytes.length % 512)) % 512;
      if (padding) blocks.push(Buffer.alloc(padding));
    }
  }
  blocks.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(blocks));
}
function fixture(t, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fea-package-audit-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const pkg = {
    name: '@marsbasex/fea', version: '1.0.0', private: false, type: 'module',
    bin: {fea: './src/cli.mjs'}, license: 'Apache-2.0', engines: {node: '>=20'},
    dependencies: {}, scripts: {}, ...overrides.package
  };
  const files = {
    'package/package.json': Buffer.from(JSON.stringify(pkg) + '\n'),
    'package/src/cli.mjs': Buffer.from('#!/usr/bin/env node\nconsole.log("ok")\n'),
    'package/src/core.mjs': Buffer.from('export const value = 1;\n'),
    'package/README.md': Buffer.from('FEA readme\n'),
    'package/README.en.md': Buffer.from('FEA readme\n'),
    'package/CHANGELOG.md': Buffer.from('Release notes\n'),
    'package/CONTRIBUTING.md': Buffer.from('Contributing\n'),
    'package/LICENSE': Buffer.from('Apache License\n'),
    'package/assets/fea-icon.png': Buffer.from([137,80,78,71,13,10,26,10])
  };
  Object.assign(files, overrides.files ?? {});
  const entries = Object.entries(files).map(([name, bytes]) => ({name, bytes}));
  if (overrides.extraEntries) entries.push(...overrides.extraEntries);
  const tarball = path.join(dir, 'marsbasex-fea-1.0.0.tgz');
  const archive = makeTar(entries);
  fs.writeFileSync(tarball, archive);
  const manifestFiles = entries.filter(e => (e.type ?? '0') === '0').map(e => ({
    path: e.name.replace(/^package\//, ''), size: Buffer.isBuffer(e.bytes) ? e.bytes.length : Buffer.byteLength(e.bytes ?? '')
  }));
  const manifest = [{
    name: '@marsbasex/fea', version: '1.0.0', filename: path.basename(tarball),
    size: archive.length, shasum: crypto.createHash('sha1').update(archive).digest('hex'),
    integrity: 'sha512-' + crypto.createHash('sha512').update(archive).digest('base64'),
    files: manifestFiles
  }];
  const manifestPath = path.join(dir, 'npm-pack.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  return {tarball, manifestPath, dir, manifest};
}

test('audits a clean package without extracting or executing it', t => {
  const f = fixture(t);
  const report = auditPackageTarball(f.tarball, f.manifestPath);
  assert.equal(report.result, 'pass');
  assert.equal(report.package.name, '@marsbasex/fea');
  assert.equal(report.package.files, 8);
  assert.equal(report.checks.pathSafetyAndRegularFilesOnly, 'pass');
  assert.equal(report.checks.lifecycleScriptsAbsent, 'pass');
});

test('rejects path traversal, symlinks and case-insensitive duplicate paths', t => {
  const traversal = fixture(t, {extraEntries: [{name: 'package/../outside.txt', bytes: 'no'}]});
  assert.throws(() => auditPackageTarball(traversal.tarball, traversal.manifestPath), /PACKAGE_PATH_TRAVERSAL/);
  const symlink = fixture(t, {extraEntries: [{name: 'package/src/evil.mjs', bytes: '', type: '2'}]});
  assert.throws(() => auditPackageTarball(symlink.tarball, symlink.manifestPath), /PACKAGE_SPECIAL_FILE_OR_LINK_FORBIDDEN/);
  const collision = fixture(t, {extraEntries: [{name: 'package/readme.md', bytes: 'different'}]});
  assert.throws(() => auditPackageTarball(collision.tarball, collision.manifestPath), /PACKAGE_DUPLICATE_OR_CASE_COLLISION/);
});

test('rejects npm metadata drift, lifecycle scripts and credential-like content', t => {
  const badManifest = fixture(t);
  const m = JSON.parse(fs.readFileSync(badManifest.manifestPath, 'utf8'));
  m[0].size += 1;
  fs.writeFileSync(badManifest.manifestPath, JSON.stringify(m));
  assert.throws(() => auditPackageTarball(badManifest.tarball, badManifest.manifestPath), /PACKAGE_NPM_SIZE_MISMATCH/);

  const lifecycle = fixture(t, {package: {scripts: {postinstall: 'node install.mjs'}}});
  assert.throws(() => auditPackageTarball(lifecycle.tarball, lifecycle.manifestPath), /PACKAGE_LIFECYCLE_SCRIPT_FORBIDDEN/);

  const secret = fixture(t, {files: {'package/README.md': Buffer.from('-----BEGIN PRIVATE KEY-----\nnot a real key\n')}});
  assert.throws(() => auditPackageTarball(secret.tarball, secret.manifestPath), /PACKAGE_CREDENTIAL_PATTERN_DETECTED/);
});

test('rejects executable payloads disguised as text and missing required files', t => {
  const executable = fixture(t, {files: {'package/README.md': Buffer.from('MZfake executable')}});
  assert.throws(() => auditPackageTarball(executable.tarball, executable.manifestPath), /PACKAGE_EXECUTABLE_BINARY_FORBIDDEN/);
  const missing = fixture(t, {files: {'package/README.md': Buffer.from('readme')}});
  const manifest = JSON.parse(fs.readFileSync(missing.manifestPath, 'utf8'));
  manifest[0].files = manifest[0].files.filter(file => file.path !== 'LICENSE');
  fs.writeFileSync(missing.manifestPath, JSON.stringify(manifest));
  const archiveWithoutLicense = makeTar(Object.entries({
    'package/package.json': Buffer.from(JSON.stringify({name:'@marsbasex/fea',version:'1.0.0',private:false,bin:{fea:'./src/cli.mjs'},license:'Apache-2.0',engines:{node:'>=20'},dependencies:{},scripts:{}})),
    'package/src/cli.mjs': Buffer.from('#!/usr/bin/env node\n'),
    'package/src/core.mjs': Buffer.from('export const x = 1;\n'),
    'package/README.md': Buffer.from('readme'),
    'package/README.en.md': Buffer.from('readme'),
    'package/CHANGELOG.md': Buffer.from('changelog'),
    'package/CONTRIBUTING.md': Buffer.from('contributing'),
    'package/assets/fea-icon.png': Buffer.from([137,80,78,71,13,10,26,10])
  }).map(([name, bytes]) => ({name, bytes})));
  fs.writeFileSync(missing.tarball, archiveWithoutLicense);
  const changedManifest = JSON.parse(fs.readFileSync(missing.manifestPath, 'utf8'));
  changedManifest[0].size = archiveWithoutLicense.length;
  changedManifest[0].shasum = crypto.createHash('sha1').update(archiveWithoutLicense).digest('hex');
  changedManifest[0].integrity = 'sha512-' + crypto.createHash('sha512').update(archiveWithoutLicense).digest('base64');
  changedManifest[0].files = changedManifest[0].files.filter(file => file.path !== 'LICENSE');
  fs.writeFileSync(missing.manifestPath, JSON.stringify(changedManifest));
  assert.throws(() => auditPackageTarball(missing.tarball, missing.manifestPath), /PACKAGE_REQUIRED_FILE_MISSING/);
});
