import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('published npm tarball passes deep package audit and produces matching SPDX SBOM', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'fea-package-audit-test-'));
  try {
    const npmCli = process.env.npm_execpath;
    assert.ok(npmCli && fs.existsSync(npmCli), 'Run this test through npm so npm_execpath is available');
    const packText = execFileSync(process.execPath, [npmCli, 'pack', '--ignore-scripts', '--json', '--pack-destination', temp], {
      cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 2000000
    });
    const pack = JSON.parse(packText);
    assert.equal(pack.length, 1);
    const tarball = path.join(temp, pack[0].filename);
    const outDir = path.join(temp, 'audit');
    const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
    const result = spawnSync(process.execPath, [
      path.join(root, 'scripts', 'package-security-audit.mjs'),
      '--tarball', tarball, '--out-dir', outDir, '--version', version
    ], {cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 2000000});
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const report = JSON.parse(fs.readFileSync(path.join(outDir, 'package-security-audit.json'), 'utf8'));
    const sbom = JSON.parse(fs.readFileSync(path.join(outDir, 'sbom.spdx.json'), 'utf8'));
    assert.equal(report.result, 'PASS');
    assert.ok(report.checks.length >= 10);
    assert.ok(report.checks.every(check => check.result === 'pass'));
    assert.equal(sbom.spdxVersion, 'SPDX-2.3');
    assert.equal(sbom.packages[0].name, '@marsbasex/fea');
    assert.equal(sbom.packages[0].versionInfo, version);
    assert.equal(sbom.packages[0].checksums[0].checksumValue, report.package.sha256);
    assert.ok(sbom.files.length > 0);
  } finally {
    fs.rmSync(temp, {recursive:true, force:true});
  }
});
