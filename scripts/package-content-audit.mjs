#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import {fileURLToPath} from 'node:url';

const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 256 * 1024 * 1024;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_FILES = 500;
const MAX_ENTRIES = 700;
const REQUIRED = [
  'src/cli.mjs', 'src/core.mjs', 'README.md', 'README.en.md',
  'CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE', 'assets/fea-icon.png'
];
const TEXT_EXTENSIONS = new Set(['.mjs', '.js', '.json', '.md', '.txt', '.yaml', '.yml', '.svg', '.html', '.css']);
const FORBIDDEN_EXTENSIONS = /\.(?:pem|key|pfx|p12|map|msi|dmg|pkg|exe|dll|so|dylib|node|app)$/i;
const FORBIDDEN_PATH = /(^|\/)(?:test|tests|demo|\.github|node_modules|tmp|\.env)(?:\/|$)/i;
const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/,
  /\bnpm_[A-Za-z0-9]{30,}\b/
];
const utf8 = new TextDecoder('utf-8', {fatal: true});
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
function fail(code) { throw new Error(code); }
function decodeField(bytes) {
  const end = bytes.indexOf(0);
  return utf8.decode(end < 0 ? bytes : bytes.subarray(0, end));
}
function octal(bytes, code) {
  if (bytes.length && (bytes[0] & 0x80)) fail(code + '_BASE256_UNSUPPORTED');
  const raw = bytes.toString('ascii').replace(/\0.*$/s, '').trim();
  if (!raw) return 0;
  if (!/^[0-7]+$/.test(raw)) fail(code + '_INVALID');
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value) || value < 0) fail(code + '_INVALID');
  return value;
}
function parsePax(data) {
  const result = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) fail('PACKAGE_PAX_RECORD_INVALID');
    const lengthText = data.toString('ascii', offset, space);
    if (!/^[1-9][0-9]*$/.test(lengthText)) fail('PACKAGE_PAX_RECORD_INVALID');
    const length = Number(lengthText);
    if (!Number.isSafeInteger(length) || length <= space - offset + 1 || offset + length > data.length) fail('PACKAGE_PAX_RECORD_INVALID');
    const record = utf8.decode(data.subarray(space + 1, offset + length)).replace(/\n$/, '');
    const eq = record.indexOf('=');
    if (eq <= 0) fail('PACKAGE_PAX_RECORD_INVALID');
    const key = record.slice(0, eq);
    if (!['path', 'size', 'mtime', 'atime', 'ctime', 'uname', 'gname', 'comment', 'charset'].includes(key)) fail('PACKAGE_PAX_KEY_UNSUPPORTED');
    result[key] = record.slice(eq + 1);
    offset += length;
  }
  return result;
}
function safePackagePath(raw) {
  if (!raw || raw.includes('\\') || raw.startsWith('/') || /^[A-Za-z]:/.test(raw)) fail('PACKAGE_PATH_ABSOLUTE_OR_INVALID');
  const stripped = raw.replace(/\/+$/, '');
  if (!stripped) fail('PACKAGE_PATH_EMPTY');
  const parts = stripped.split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) fail('PACKAGE_PATH_TRAVERSAL');
  if (parts[0] !== 'package') fail('PACKAGE_PATH_OUTSIDE_ROOT');
  if (parts.length === 1) return '';
  if (parts.length > 16 || stripped.length > 240) fail('PACKAGE_PATH_LIMIT');
  return parts.slice(1).join('/');
}
function parseTar(tar) {
  const files = new Map();
  const seen = new Map();
  let offset = 0, entries = 0, totalFileBytes = 0, pendingPax = null, ended = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      ended = true;
      if (!tar.subarray(offset).every(byte => byte === 0)) fail('PACKAGE_TAR_TRAILING_DATA');
      break;
    }
    entries++;
    if (entries > MAX_ENTRIES) fail('PACKAGE_ENTRY_COUNT_LIMIT');
    const storedChecksum = octal(header.subarray(148, 156), 'PACKAGE_TAR_CHECKSUM');
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : header[i];
    if (checksum !== storedChecksum) fail('PACKAGE_TAR_CHECKSUM_MISMATCH');
    const name = decodeField(header.subarray(0, 100));
    const prefix = decodeField(header.subarray(345, 500));
    const rawPath = prefix ? prefix + '/' + name : name;
    const typeByte = header[156];
    const type = typeByte === 0 ? '0' : String.fromCharCode(typeByte);
    const headerSize = octal(header.subarray(124, 136), 'PACKAGE_TAR_SIZE');
    const mode = octal(header.subarray(100, 108), 'PACKAGE_TAR_MODE');
    if (headerSize > MAX_EXPANDED_BYTES) fail('PACKAGE_FILE_SIZE_LIMIT');
    const dataStart = offset + 512;
    const dataEnd = dataStart + headerSize;
    if (dataEnd > tar.length) fail('PACKAGE_TAR_TRUNCATED');
    const data = tar.subarray(dataStart, dataEnd);
    if (type === 'x') {
      if (pendingPax) fail('PACKAGE_PAX_NESTED_UNSUPPORTED');
      if (headerSize > 1024 * 1024) fail('PACKAGE_PAX_SIZE_LIMIT');
      pendingPax = parsePax(data);
      offset = dataStart + Math.ceil(headerSize / 512) * 512;
      continue;
    }
    if (type === 'g' || type === 'L' || type === 'K') fail('PACKAGE_TAR_METADATA_UNSUPPORTED');
    let effectivePath = rawPath;
    let effectiveSize = headerSize;
    if (pendingPax) {
      if (pendingPax.path !== undefined) effectivePath = pendingPax.path;
      if (pendingPax.size !== undefined) {
        if (!/^(0|[1-9][0-9]*)$/.test(pendingPax.size) || Number(pendingPax.size) !== headerSize) fail('PACKAGE_PAX_SIZE_MISMATCH');
        effectiveSize = Number(pendingPax.size);
      }
      pendingPax = null;
    }
    const rel = safePackagePath(effectivePath);
    if (!rel) {
      if (type !== '5' || effectiveSize !== 0) fail('PACKAGE_ROOT_ENTRY_INVALID');
      offset = dataStart + Math.ceil(headerSize / 512) * 512;
      continue;
    }
    const key = rel.toLocaleLowerCase('en-US');
    if (seen.has(key)) fail('PACKAGE_DUPLICATE_OR_CASE_COLLISION');
    seen.set(key, type);
    if (type === '5') {
      if (effectiveSize !== 0) fail('PACKAGE_DIRECTORY_HAS_CONTENT');
    } else if (type === '0') {
      if (files.size >= MAX_FILES) fail('PACKAGE_FILE_COUNT_LIMIT');
      if (effectiveSize > MAX_FILE_BYTES) fail('PACKAGE_FILE_SIZE_LIMIT');
      if ((mode & 0o6000) !== 0 || (mode & 0o002) !== 0) fail('PACKAGE_UNSAFE_FILE_MODE');
      totalFileBytes += effectiveSize;
      if (totalFileBytes > MAX_EXPANDED_BYTES) fail('PACKAGE_TOTAL_SIZE_LIMIT');
      files.set(rel, {path: rel, size: effectiveSize, mode: mode & 0o777, bytes: Buffer.from(data), sha256: sha256(data)});
    } else {
      fail('PACKAGE_SPECIAL_FILE_OR_LINK_FORBIDDEN');
    }
    offset = dataStart + Math.ceil(headerSize / 512) * 512;
  }
  if (!ended) fail('PACKAGE_TAR_END_MARKER_MISSING');
  if (pendingPax) fail('PACKAGE_PAX_WITHOUT_ENTRY');
  if (!files.size) fail('PACKAGE_EMPTY');
  return {files, totalFileBytes, entries};
}
function inspectTextAndBinaries(files) {
  const textDecoder = new TextDecoder('utf-8', {fatal: true});
  for (const file of files.values()) {
    if (FORBIDDEN_PATH.test(file.path) || FORBIDDEN_EXTENSIONS.test(file.path) || /(^|\/)\.env(?:\.[^/]*)?$/i.test(file.path)) {
      fail('PACKAGE_FORBIDDEN_FILE_PATH');
    }
    const lower = file.path.toLowerCase();
    if (lower.endsWith('.png')) {
      if (file.bytes.length < 8 || !file.bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) fail('PACKAGE_PNG_SIGNATURE_INVALID');
      continue;
    }
    if (file.bytes.subarray(0, 2).toString('ascii') === 'MZ' ||
        file.bytes.subarray(0, 4).equals(Buffer.from([0x7f,0x45,0x4c,0x46])) ||
        ['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca'].includes(file.bytes.subarray(0,4).toString('hex'))) {
      fail('PACKAGE_EXECUTABLE_BINARY_FORBIDDEN');
    }
    if (file.bytes.includes(0)) fail('PACKAGE_BINARY_FILE_FORBIDDEN');
    let text;
    try { text = textDecoder.decode(file.bytes); } catch { fail('PACKAGE_NON_UTF8_CONTENT_FORBIDDEN'); }
    if (TEXT_EXTENSIONS.has(path.extname(lower)) || lower === 'license' || lower === 'notice') {
      for (const pattern of SECRET_PATTERNS) if (pattern.test(text)) fail('PACKAGE_CREDENTIAL_PATTERN_DETECTED');
    }
    if (lower.endsWith('.svg') && (/<script\b|\bon[a-z]+\s*=|javascript:/i.test(text) || /\b(?:href|src)\s*=\s*["']https?:/i.test(text))) {
      fail('PACKAGE_ACTIVE_OR_REMOTE_SVG_CONTENT');
    }
  }
}
function parseArgs(argv) {
  const positional = [], flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) { positional.push(arg); continue; }
    const key = arg.slice(2);
    if (!['manifest','out'].includes(key) || Object.hasOwn(flags, key) || !argv[i + 1] || argv[i + 1].startsWith('--')) fail('PACKAGE_AUDIT_INVALID_FLAG');
    flags[key] = argv[++i];
  }
  if (positional.length !== 1 || !flags.manifest || !flags.out) fail('Usage: node scripts/package-content-audit.mjs <package.tgz> --manifest <npm-pack.json> --out <report.json>');
  return {tarball: positional[0], manifestPath: flags.manifest, out: flags.out};
}
export function auditPackageTarball(tarballPath, manifestPath) {
  const absolute = path.resolve(tarballPath);
  const st = fs.lstatSync(absolute);
  if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) fail('PACKAGE_ARCHIVE_REGULAR_FILE_REQUIRED');
  if (st.size < 1 || st.size > MAX_ARCHIVE_BYTES) fail('PACKAGE_ARCHIVE_SIZE_LIMIT');
  const compressed = fs.readFileSync(absolute);
  let expanded;
  try { expanded = zlib.gunzipSync(compressed, {maxOutputLength: MAX_EXPANDED_BYTES}); } catch { fail('PACKAGE_GZIP_INVALID_OR_EXPANSION_LIMIT'); }
  const parsed = parseTar(expanded);
  inspectTextAndBinaries(parsed.files);
  const manifestStat = fs.lstatSync(manifestPath);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 1024 * 1024) fail('PACKAGE_MANIFEST_UNSAFE');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (!Array.isArray(manifest) || manifest.length !== 1) fail('PACKAGE_MANIFEST_SHAPE_INVALID');
  const item = manifest[0];
  const pkgFile = parsed.files.get('package.json');
  if (!pkgFile) fail('PACKAGE_JSON_MISSING');
  let pkg;
  try { pkg = JSON.parse(utf8.decode(pkgFile.bytes)); } catch { fail('PACKAGE_JSON_INVALID'); }
  if (item.name !== '@marsbasex/fea' || item.version !== pkg.version || item.filename !== path.basename(absolute)) fail('PACKAGE_NPM_METADATA_MISMATCH');
  if (!Number.isSafeInteger(item.size) || item.size !== compressed.length) fail('PACKAGE_NPM_SIZE_MISMATCH');
  if (item.shasum !== crypto.createHash('sha1').update(compressed).digest('hex')) fail('PACKAGE_NPM_SHA1_MISMATCH');
  if (item.integrity !== 'sha512-' + crypto.createHash('sha512').update(compressed).digest('base64')) fail('PACKAGE_NPM_SHA512_MISMATCH');
  if (pkg.name !== item.name || pkg.private !== false || pkg.bin?.fea !== './src/cli.mjs' || pkg.license !== 'Apache-2.0') fail('PACKAGE_METADATA_POLICY_FAILED');
  if (typeof pkg.engines?.node !== 'string' || !/^>=\s*20(?:\.0(?:\.0)?)?$/.test(pkg.engines.node.trim())) fail('PACKAGE_NODE_ENGINE_POLICY_FAILED');
  if (Object.keys(pkg.dependencies ?? {}).length || Object.keys(pkg.optionalDependencies ?? {}).length || Object.keys(pkg.peerDependencies ?? {}).length || Object.keys(pkg.bundledDependencies ?? {}).length) fail('PACKAGE_RUNTIME_DEPENDENCIES_NOT_ALLOWED');
  const scripts = pkg.scripts ?? {};
  const lifecycle = ['preinstall','install','postinstall','prepare','prepublish','prepublishOnly'];
  if (lifecycle.some(key => Object.hasOwn(scripts, key))) fail('PACKAGE_LIFECYCLE_SCRIPT_FORBIDDEN');
  for (const required of REQUIRED) if (!parsed.files.has(required)) fail('PACKAGE_REQUIRED_FILE_MISSING');
  const expected = new Map();
  if (!Array.isArray(item.files)) fail('PACKAGE_NPM_FILE_MANIFEST_INVALID');
  for (const file of item.files) {
    if (!file || typeof file.path !== 'string' || !Number.isSafeInteger(file.size) || file.size < 0 || expected.has(file.path)) fail('PACKAGE_NPM_FILE_MANIFEST_INVALID');
    expected.set(file.path, file.size);
  }
  if (expected.size !== parsed.files.size) fail('PACKAGE_FILE_SET_MISMATCH');
  for (const [name, file] of parsed.files) {
    if (!expected.has(name) || expected.get(name) !== file.size) fail('PACKAGE_FILE_MANIFEST_MISMATCH');
  }
  if (parsed.files.size >= 140) fail('PACKAGE_FILE_COUNT_POLICY_FAILED');
  const sorted = [...parsed.files.values()].sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return {
    formatVersion: 1,
    kind: 'fea-npm-package-content-audit',
    result: 'pass',
    package: {name: pkg.name, version: pkg.version, compressedBytes: compressed.length, unpackedBytes: parsed.totalFileBytes, files: parsed.files.size},
    checks: {
      gzipAndTarStructure: 'pass', pathSafetyAndRegularFilesOnly: 'pass', npmManifestAndIntegrity: 'pass',
      packageMetadataAndRuntimeDependencies: 'pass', lifecycleScriptsAbsent: 'pass', sensitiveAndExecutableFilesAbsent: 'pass',
      textAndCredentialPatternScan: 'pass', svgActiveContentCheck: 'pass', requiredFilesPresent: 'pass'
    },
    fileInventory: sorted.map(file => ({path: file.path, size: file.size, mode: file.mode, sha256: file.sha256})),
    limitations: [
      'This inspects the npm tarball without extracting or executing it.',
      'Credential pattern checks are heuristic and do not prove the absence of secrets.',
      'It does not scan transitive dependencies because this package intentionally declares no runtime dependencies.',
      'It is not a malware scan, code-signing check, or security certification.'
    ]
  };
}
function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const tarball = path.resolve(args.tarball);
    const manifest = path.resolve(args.manifestPath);
    const out = path.resolve(args.out);
    if (out === tarball || out === manifest) fail('PACKAGE_AUDIT_OUTPUT_OVERLAPS_INPUT');
    const report = auditPackageTarball(tarball, manifest);
    fs.mkdirSync(path.dirname(out), {recursive: true});
    fs.writeFileSync(out, JSON.stringify(report, null, 2) + '\n');
    console.log('FEA PACKAGE CONTENT AUDIT PASS', JSON.stringify(report.package));
  } catch (error) {
    console.error('FEA PACKAGE CONTENT AUDIT FAIL', error.message);
    process.exitCode = 1;
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) main();
