#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

// CI-owned packaging smoke test. No external network, npm lifecycle scripts or third-party app execution.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npmCli = process.env.npm_execpath;
if (!npmCli || !fs.existsSync(npmCli)) {
  console.error('Run this check with npm run distribution:smoke (npm_execpath required).');
  process.exitCode = 1;
} else {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'fea-distribution-'));
  const invoke = (args, cwd = root, timeout = 60_000) => {
    const p = spawnSync(process.execPath, [npmCli, ...args], {
      cwd, env: {...process.env, npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false'},
      encoding: 'utf8', timeout, maxBuffer: 2_000_000, windowsHide: true
    });
    assert.equal(p.status, 0, `npm ${args[0]} failed: ${(p.stderr || p.error?.message || '').slice(0, 1600)}`);
    return p.stdout;
  };
  const runNode = (args, code = 0) => {
    const p = spawnSync(process.execPath, args, {cwd: scratch, encoding:'utf8', timeout: 20_000, maxBuffer: 500_000, windowsHide: true});
    assert.equal(p.status, code, `FEA command failed: ${args.slice(1, 4).join(' ')} (${p.status})\n${p.stderr || ''}`);
    return p.stdout;
  };
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    assert.match(meta.name, /^@[a-z0-9-]+\/[a-z0-9-]+$/);
    assert.equal(meta.private, false, 'Distribution must be intentionally packable');
    assert.equal(meta.bin?.fea, './src/cli.mjs');
    assert.deepEqual(meta.dependencies ?? {}, {}, 'The base CLI must be dependency-free');
    const packText = invoke(['pack', '--json', '--ignore-scripts', '--pack-destination', scratch], root, 90_000);
    const result = JSON.parse(packText);
    assert.equal(result.length, 1);
    const item = result[0];
    const included = new Set(item.files.map(f => f.path));
    for (const required of ['src/cli.mjs','src/core.mjs','README.md','README.en.md','CHANGELOG.md','CONTRIBUTING.md','LICENSE','assets/fea-icon.png']) {
      assert(included.has(required), `Required distributable file missing: ${required}`);
    }
    for (const readme of ['README.md','README.en.md']) {
      const markdown = fs.readFileSync(path.join(root, readme), 'utf8');
      const localMarkdownLinks = [...markdown.matchAll(/\]\(([^)#]+\.md)(?:#[^)]+)?\)/g)]
        .map(match => match[1])
        .filter(target => !/^https?:\/\//i.test(target));
      for (const link of localMarkdownLinks) {
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(readme), link.split('#')[0]));
        assert(included.has(target), `README link target missing from npm tarball: ${target} (referenced by ${readme})`);
      }
    }
    assert(included.size < 140, 'Unexpectedly large package manifest');
    assert([...included].every(f => !/(^|\/)(?:test|tests|demo|\.github|\.env|node_modules|tmp)(?:\/|$)/i.test(f)), 'Private or test-only files in npm tarball');
    assert(![...included].some(f => /(?:\.pem|\.key|\.pfx|\.p12|\.map)$/i.test(f)), 'Secret-like or sourcemap file in tarball');
    const tarball = path.join(scratch, item.filename);
    assert(fs.statSync(tarball).size > 0);
    const prefix = path.join(scratch, 'installed');
    invoke(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', prefix, tarball], scratch, 90_000);
    const executable = path.join(prefix, 'node_modules', '@marsbasex', 'fea', 'src', 'cli.mjs');
    assert(fs.statSync(executable).isFile(), 'Installed package lacks the CLI entry point');
    const binaryDir = path.join(prefix, 'node_modules', '.bin');
    assert(fs.existsSync(path.join(binaryDir, process.platform === 'win32' ? 'fea.cmd' : 'fea')), 'npm CLI shim missing');
    assert.match(runNode([executable, '--help']), /fea scan/);
    const config = path.join(scratch, 'fea.json');
    runNode([executable, 'init', '--out', config]);
    const resources = path.join(scratch, 'resources');
    fs.mkdirSync(resources);
    fs.writeFileSync(path.join(resources, 'index.js'), 'console.log("FEA distribution smoke")\n');
    const reports = path.join(scratch, 'audit');
    runNode([executable, 'scan', resources, '--config', config, '--out', reports]);
    runNode([executable, 'verify', path.join(reports, 'report.json'), '--policy', config]);
    const cleanReport = JSON.parse(fs.readFileSync(path.join(reports, 'report.json'), 'utf8'));
    assert.equal(cleanReport.coverage.complete, true);
    assert.equal(cleanReport.findings.length, 0);
    const artifact = {version: meta.version, tarball: item.filename, files:included.size,
      unpackedBytes:item.unpackedSize, shasum:item.shasum, integrity:item.integrity,
      verified: {offlineInstall: true, npmBinShim: true, cliHelp: true, scan: true, policyGate: true},
      notice: 'Package installation and basic CLI smoke test only. Not a security audit or signed release.'};
    const out = process.env.FEA_DISTRIBUTION_REPORT;
    if(out) {fs.mkdirSync(path.dirname(path.resolve(out)),{recursive:true});fs.writeFileSync(out,JSON.stringify(artifact,null,2)+'\n');}
    console.log('FEA DISTRIBUTION PASS', JSON.stringify(artifact));
  } catch (error) {
    console.error('FEA DISTRIBUTION FAIL', error.message);
    process.exitCode = 1;
  } finally {
    fs.rmSync(scratch, {recursive:true, force:true});
  }
}
