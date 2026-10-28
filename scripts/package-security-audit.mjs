#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const allowed = new Set(['--tarball', '--out-dir', '--version']);
const flags = {};
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (!arg.startsWith('--') || !allowed.has(arg) || flags[arg] || !args[i + 1] || args[i + 1].startsWith('--')) {
    console.error('Usage: node scripts/package-security-audit.mjs --tarball <file.tgz> --out-dir <dir> --version <semver>');
    process.exit(2);
  }
  flags[arg] = args[++i];
}
if (!flags['--tarball'] || !flags['--out-dir'] || !/^\d+\.\d+\.\d+$/.test(flags['--version'] ?? '')) {
  console.error('Usage: node scripts/package-security-audit.mjs --tarball <file.tgz> --out-dir <dir> --version <semver>');
  process.exit(2);
}

const tarball = path.resolve(flags['--tarball']);
const outDir = path.resolve(flags['--out-dir']);
const version = flags['--version'];
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const fail = [];
const checks = [];
const check = (name, ok, detail) => { checks.push({name, result: ok ? 'pass' : 'fail', detail}); if (!ok) fail.push(name); };
const run = (command, commandArgs) => {
  const result = spawnSync(command, commandArgs, {encoding:'utf8', maxBuffer:8_000_000, windowsHide:true});
  if (result.error || result.status !== 0) throw new Error('PACKAGE_AUDIT_ARCHIVE_ERROR');
  return result.stdout;
};
if (!fs.existsSync(tarball) || !fs.statSync(tarball).isFile()) throw new Error('PACKAGE_AUDIT_TARBALL_MISSING');
const bytes = fs.readFileSync(tarball);
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'fea-package-audit-'));
try {
  const entries = run('tar', ['-tzf', tarball]).split(/\r?\n/).filter(Boolean);
  const names = entries.map(entry => entry.replace(/^package\//, '').replace(/\/$/, ''));
  check('archive-has-files', names.length > 0 && names.every(Boolean), 'Archive has a non-empty file list.');
  check('archive-paths-contained', entries.every(entry => !entry.startsWith('/') && !entry.split('/').some(part => part === '..') && !entry.includes('\\')), 'No absolute paths, parent traversal, or backslash paths.');
  check('archive-root-is-package', entries.every(entry => entry === 'package' || entry.startsWith('package/')), 'All entries are rooted under package/.');
  const normalized = names.filter(Boolean);
  check('archive-has-no-duplicate-paths', new Set(normalized).size === normalized.length, 'Archive entry paths are unique.');
  const listing = run('tar', ['-tvzf', tarball]).split(/\r?\n/).filter(Boolean);
  check('archive-has-no-links', listing.every(line => !/^[lh]/.test(line)), 'No symbolic or hard links in the published archive.');
  const extractDir = path.join(temp, 'extract');
  fs.mkdirSync(extractDir);
  run('tar', ['--no-same-owner', '--no-same-permissions', '-xzf', tarball, '-C', extractDir]);
  const packageDir = path.join(extractDir, 'package');
  const packedPkgPath = path.join(packageDir, 'package.json');
  check('package-metadata-present', fs.existsSync(packedPkgPath), 'package/package.json exists.');
  const packedPkg = JSON.parse(fs.readFileSync(packedPkgPath, 'utf8'));
  check('package-name-version-match', packedPkg.name === pkg.name && packedPkg.version === version && pkg.version === version, 'Name/version match repository metadata and requested release version.');
  check('no-install-lifecycle-scripts', !['preinstall','install','postinstall','prepare'].some(key => Object.hasOwn(packedPkg.scripts ?? {}, key)), 'No npm install-time lifecycle scripts.');
  check('dependency-free-cli', Object.keys(packedPkg.dependencies ?? {}).length === 0, 'Published CLI declares no runtime dependencies.');
  check('bin-entry-point', packedPkg.bin?.fea === './src/cli.mjs' && fs.existsSync(path.join(packageDir, 'src/cli.mjs')), 'CLI executable maps to a shipped entry point.');
  const required = ['src/cli.mjs','src/core.mjs','README.md','README.en.md','CHANGELOG.md','CONTRIBUTING.md','SECURITY.md','LICENSE','assets/fea-icon.png'];
  check('required-files-present', required.every(file => normalized.includes(file)), 'Required user-facing and runtime files are included.');
  const forbidden = normalized.filter(file => /(^|\/)(?:test|tests|demo|\.github|node_modules|tmp|coverage)(?:\/|$)/i.test(file) || /(?:\.pem|\.key|\.pfx|\.p12|\.map)$/i.test(file) || /(^|\/)\.env(?:\.|$)/i.test(file));
  check('no-private-or-build-files', forbidden.length === 0, forbidden.length ? 'Unexpected paths: ' + forbidden.slice(0, 12).join(', ') : 'No test, demo, credential, source-map, or build-only files detected.');
  const secretPatterns = [
    ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
    ['github-token', /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/],
    ['github-fine-grained-token', /\bgithub_pat_[A-Za-z0-9_]{30,}\b/],
    ['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/],
  ];
  const textFiles = normalized.filter(file => /\.(?:mjs|cjs|js|json|md|txt|ya?ml|toml|html|css|sh|ps1)$/i.test(file));
  const findings = [];
  for (const file of textFiles) {
    const full = path.join(packageDir, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const content = fs.readFileSync(full, 'utf8');
    for (const [kind, pattern] of secretPatterns) if (pattern.test(content)) findings.push({kind, file});
  }
  check('no-obvious-secrets', findings.length === 0, findings.length ? 'Potential secret patterns in: ' + [...new Set(findings.map(f => f.file))].slice(0, 10).join(', ') : 'No high-confidence credential patterns detected.');
  const files = [];
  for (const file of [...new Set(normalized)].sort()) {
    const full = path.join(packageDir, file);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const content = fs.readFileSync(full);
    files.push({
      fileName: 'package/' + file,
      fileType: /\.(?:mjs|cjs|js)$/i.test(file) ? 'SOURCE' : /\.(?:png|jpe?g|svg|webp)$/i.test(file) ? 'IMAGE' : 'OTHER',
      checksums: [{algorithm:'SHA256', checksumValue:crypto.createHash('sha256').update(content).digest('hex')}],
      licenseConcluded: 'NOASSERTION',
      licenseInfoInFile: ['NOASSERTION'],
      copyrightText: 'NOASSERTION'
    });
  }
  const spdx = {
    spdxVersion:'SPDX-2.3',
    dataLicense:'CC0-1.0',
    SPDXID:'SPDXRef-DOCUMENT',
    name: pkg.name + '-' + version + '-npm-package',
    documentNamespace:'https://marsbasex.com/spdx/' + encodeURIComponent(pkg.name) + '/' + version + '/' + sha256,
    creationInfo:{creators:['Tool: FEA-package-security-audit'], created:new Date().toISOString()},
    packages:[{
      name:pkg.name,
      SPDXID:'SPDXRef-Package',
      versionInfo:version,
      downloadLocation:'NOASSERTION',
      filesAnalyzed:true,
      checksums:[{algorithm:'SHA256',checksumValue:sha256}],
      licenseConcluded:pkg.license ?? 'NOASSERTION',
      licenseDeclared:pkg.license ?? 'NOASSERTION',
      copyrightText:'NOASSERTION'
    }],
    files,
    relationships:[{spdxElementId:'SPDXRef-DOCUMENT',relationshipType:'DESCRIBES',relatedSpdxElement:'SPDXRef-Package'}]
  };
  const report = {
    schemaVersion:1,
    package:{name:pkg.name,version,filename:path.basename(tarball),size:bytes.length,sha256},
    result:fail.length ? 'FAIL' : 'PASS',
    checks,
    secretFindings:findings,
    limitations:[
      'Static package-content screening only; not malware analysis or a complete vulnerability audit.',
      'SPDX file records use NOASSERTION for per-file license/copyright metadata.',
      'Does not establish Authenticode signing, Apple Developer ID signing, macOS notarization, or SmartScreen reputation.'
    ]
  };
  fs.mkdirSync(outDir,{recursive:true});
  fs.writeFileSync(path.join(outDir,'package-security-audit.json'),JSON.stringify(report,null,2)+'\n');
  fs.writeFileSync(path.join(outDir,'sbom.spdx.json'),JSON.stringify(spdx,null,2)+'\n');
  console.log('FEA PACKAGE AUDIT ' + report.result + ' (' + checks.filter(c => c.result === 'pass').length + '/' + checks.length + ' checks)');
  console.log('SBOM: ' + path.join(outDir,'sbom.spdx.json'));
  if (fail.length) { console.error('Failed checks: ' + fail.join(', ')); process.exitCode=1; }
} finally {
  fs.rmSync(temp,{recursive:true,force:true});
}
