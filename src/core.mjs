import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const VERSION = '0.3.3-alpha.1';
export const RULES = Object.freeze({
  FEA001: {title:'Source map shipped', severity:'high'},
  FEA002: {title:'Potential private key in release', severity:'critical'},
  FEA003: {title:'Internal configuration in release', severity:'high'},
  FEA004: {title:'Debug symbol or diagnostic artifact', severity:'medium'},
  FEA005: {title:'Development or test asset in release', severity:'medium'}
});
export const DEFAULT_CONFIG = Object.freeze({
  schemaVersion:1,
  profile:'electron-resources',
  inputStage:'prepackage',
  limits:{maxFiles:20000,maxFileBytes:4194304,maxTotalBytes:209715200,maxDurationMs:30000},
  policy:{block:Object.keys(RULES),exceptions:[]}
});
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const isInside = (parent, child) => child === parent || child.startsWith(parent + path.sep);
const textSuffix = /\.(?:js|mjs|cjs|json|map|txt|env|yaml|yml|xml|properties|ts|tsx|jsx|pem|key|md|html|css)$/i;
const sourcemap = /\.map$/i;
const keyMarker = /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/;
const internalName = /(?:^\.env(?:\..+)?$|(?:^|[._-])internal(?:[._-]|$)|(?:^|[._-])secret(?:s)?(?:[._-]|$))/i;
const internalText = /\b(?:INTERNAL_(?:API|URL|TOKEN|SECRET)|PRIVATE_API_(?:KEY|URL)|SERVER_SECRET)\b/i;
const debugName = /(?:\.pdb|\.ilk|\.dSYM(?:\/|$)|\.debug)$/i;
const devAsset = /(?:^|\/)(?:__tests__|__mocks__|tests?|fixtures|e2e)(?:\/|$)|\.(?:spec|test)\.[cm]?[jt]sx?$/i;

// Shared file rule engine for resource directories and bounded ASAR entries.
// This never executes source code or returns raw candidate-secret content.
export function inspectAsset(relative, bytes) {
  const found = new Set();
  const base = relative.split('/').at(-1);
  if (sourcemap.test(base)) found.add('FEA001');
  if (debugName.test(relative)) found.add('FEA004');
  if (devAsset.test(relative)) found.add('FEA005');
  if (internalName.test(base)) found.add('FEA003');
  let textInspected = false;
  let opaqueText = false;
  if (textSuffix.test(base) || base.startsWith('.env')) {
    textInspected = true;
    if (bytes.includes(0)) opaqueText = true;
    else {
      const content = bytes.toString('utf8');
      if (keyMarker.test(content)) found.add('FEA002');
      if (!internalName.test(base) && internalText.test(content)) found.add('FEA003');
      if (/\bsourceMappingURL\s*=/.test(content) && !sourcemap.test(base)) found.add('FEA001');
    }
  }
  return {ruleIds:[...found], textInspected, opaqueText};
}

export function validateConfig(config) {
  if (!config || config.schemaVersion !== 1 || config.profile !== 'electron-resources' ||
      !['prepackage','developer-extracted'].includes(config.inputStage)) throw Error('Unsupported config version, profile or inputStage');
  const limits = config.limits;
  if (!limits || ['maxFiles','maxFileBytes','maxTotalBytes','maxDurationMs'].some(k => !Number.isSafeInteger(limits[k]) || limits[k] < 1)) throw Error('Invalid scan limits');
  if (!config.policy || !Array.isArray(config.policy.block) || !Array.isArray(config.policy.exceptions) ||
      config.policy.block.some(id => !RULES[id])) throw Error('Invalid policy');
  for (const x of config.policy.exceptions) {
    if (!x || !RULES[x.ruleId] || !/^[a-f0-9]{16}$/.test(x.pathId || '') ||
        typeof x.owner !== 'string' || !x.owner.trim() || typeof x.reason !== 'string' || !x.reason.trim() ||
        typeof x.expires !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(x.expires) ||
        !Number.isFinite(Date.parse(x.expires + 'T23:59:59Z'))) throw Error('Invalid exception (requires ruleId, pathId, owner, reason, expires)');
  }
  return config;
}
export function readConfig(file) { return validateConfig(JSON.parse(fs.readFileSync(file,'utf8'))); }

export function scanDirectory(rootInput, config, options={}) {
  validateConfig(config);
  if (fs.lstatSync(rootInput).isSymbolicLink()) throw Error('Input root must not be a symlink');
  const root = fs.realpathSync(rootInput);
  if (!fs.statSync(root).isDirectory()) throw Error('Input must be a directory');
  if (path.extname(root).toLowerCase() === '.asar') throw Error('Raw ASAR input is unsupported in v0.1');
  if (options.out) {
    const out = path.resolve(options.out);
    let parent = out;
    while (!fs.existsSync(parent)) {const next=path.dirname(parent); if(next===parent)break; parent=next;}
    if (isInside(root, fs.realpathSync(parent))) throw Error('Output must be outside the scan root');
  }
  const since = Date.now(), entries=[], findings=[], errors=[];
  let scanned=0, inspectedTextFiles=0, totalBytes=0, opaqueFiles=0;
  const issue = (code) => {if (!errors.includes(code)) errors.push(code);};
  const add = (ruleId, relative, note) => {
    const pathId=hash(relative).slice(0,16);
    findings.push({ruleId,severity:RULES[ruleId].severity,pathId,
      fingerprint:hash(ruleId + ':' + pathId).slice(0,20),message:note || RULES[ruleId].title});
  };
  function visit(directory) {
    if (Date.now()-since>config.limits.maxDurationMs) {issue('TIME_LIMIT');return;}
    let names;
    try {names=fs.readdirSync(directory,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name,'en'));}
    catch {issue('READ_ERROR');return;}
    for (const entry of names) {
      if (errors.length) return;
      const file=path.join(directory,entry.name), relative=path.relative(root,file).split(path.sep).join('/');
      let stat;
      try {stat=fs.lstatSync(file);} catch {issue('READ_ERROR');return;}
      if (stat.isSymbolicLink()) {issue('SYMLINK_UNSUPPORTED');return;}
      if (stat.isDirectory()) {visit(file); continue;}
      if (!stat.isFile()) {issue('SPECIAL_FILE_UNSUPPORTED');return;}
      if (++scanned>config.limits.maxFiles) {issue('FILE_LIMIT');return;}
      totalBytes+=stat.size;
      if (totalBytes>config.limits.maxTotalBytes) {issue('TOTAL_BYTE_LIMIT');return;}
      if (stat.size>config.limits.maxFileBytes) {issue('FILE_BYTE_LIMIT');return;}
      let bytes;
      try {bytes=fs.readFileSync(file);}catch {issue('READ_ERROR');return;}
      let after;
      try {after=fs.lstatSync(file);}catch {issue('READ_ERROR');return;}
      if (!after.isFile() || after.size!==stat.size || after.mtimeMs!==stat.mtimeMs || bytes.length!==stat.size) {issue('INPUT_CHANGED');return;}
      entries.push(hash(relative)+':'+hash(bytes));
      const assessment = inspectAsset(relative,bytes);
      if (assessment.textInspected) inspectedTextFiles++;
      if (assessment.opaqueText) {opaqueFiles++;issue('OPAQUE_TEXT');return;}
      for(const ruleId of assessment.ruleIds) add(ruleId,relative);
      if (Date.now()-since>config.limits.maxDurationMs) {issue('TIME_LIMIT');return;}
    }
  }
  visit(root);
  const unique=new Map(findings.map(f=>[f.ruleId+':'+f.pathId,f]));
  const sorted=[...unique.values()].sort((a,b)=>a.ruleId.localeCompare(b.ruleId)||a.pathId.localeCompare(b.pathId));
  return {
    formatVersion:1,scannerVersion:VERSION,profile:'electron-resources',inputStage:config.inputStage,
    generatedAt:new Date().toISOString(),
    inputDigest:hash(entries.sort().join('\n')),
    coverage:{complete:errors.length===0,ruleIds:Object.keys(RULES),scannedFiles:scanned,inspectedTextFiles,opaqueFiles,errors:errors.sort()},
    findings:sorted
  };
}
export function validateReport(report) {
  if (!report || report.formatVersion!==1 || report.profile!=='electron-resources' ||
      !Array.isArray(report.findings) || !report.coverage || !Array.isArray(report.coverage.ruleIds) ||
      !Array.isArray(report.coverage.errors) || typeof report.coverage.complete!=='boolean' ||
      typeof report.inputDigest!=='string' || !['prepackage','developer-extracted'].includes(report.inputStage)) throw Error('Unsupported or incomplete report');
  for (const f of report.findings) if (!RULES[f.ruleId] || !/^[a-f0-9]{16}$/.test(f.pathId || '') ||
    !/^[a-f0-9]{20}$/.test(f.fingerprint || '')) throw Error('Malformed findings');
  return report;
}
export function verifyReport(report, config, now=new Date()) {
  validateReport(report);validateConfig(config);
  const problems=[];
  if (report.inputStage!==config.inputStage) problems.push('INPUT_STAGE_MISMATCH');
  if (!report.coverage.complete || report.coverage.errors.length) problems.push('INCOMPLETE_SCAN');
  for (const id of Object.keys(RULES)) if (!report.coverage.ruleIds.includes(id)) problems.push('RULE_COVERAGE_MISSING:'+id);
  const blocking=[];
  for (const f of report.findings) {
    if (!config.policy.block.includes(f.ruleId)) continue;
    const exception=config.policy.exceptions.find(x=>x.ruleId===f.ruleId && x.pathId===f.pathId &&
      now.getTime()<=Date.parse(x.expires+'T23:59:59Z'));
    if (!exception) blocking.push({ruleId:f.ruleId,pathId:f.pathId});
  }
  return {ok:problems.length===0 && blocking.length===0,problems,blocking,blockedCount:blocking.length,
    notice:'Policy checks assume the report originated in a trusted CI context; this JSON is not authenticated.'};
}
export function compareReports(before, after) {
  validateReport(before);validateReport(after);
  if (!before.coverage.complete || !after.coverage.complete || before.coverage.errors.length || after.coverage.errors.length) throw Error('Cannot compare incomplete scans');
  if (before.inputStage!==after.inputStage || before.coverage.ruleIds.join(',')!==after.coverage.ruleIds.join(',')) throw Error('Incompatible scan coverage');
  const old=new Set(before.findings.map(f=>f.fingerprint)), current=new Set(after.findings.map(f=>f.fingerprint));
  const rules=Object.keys(RULES).map(id=>({ruleId:id,title:RULES[id].title,
    before:before.findings.filter(x=>x.ruleId===id).length,after:after.findings.filter(x=>x.ruleId===id).length}));
  return {formatVersion:1,beforeDigest:before.inputDigest,afterDigest:after.inputDigest,inputStage:before.inputStage,
    beforeCount:old.size,afterCount:current.size,resolved:[...old].filter(x=>!current.has(x)).length,
    introduced:[...current].filter(x=>!old.has(x)).length,remaining:[...current].filter(x=>old.has(x)).length,
    rules,notice:'Observed findings only. This does not establish resistance to reverse engineering.'};
}
export function comparisonMarkdown(c) {
  return ['# FEA before / after comparison','',
    'Input stage: `'+c.inputStage+'`','',
    '| Metric | Count |','| --- | ---: |',
    '| Before findings | '+c.beforeCount+' |','| After findings | '+c.afterCount+' |',
    '| Resolved | '+c.resolved+' |','| Introduced | '+c.introduced+' |','| Remaining | '+c.remaining+' |',
    '', '| Rule | Before | After |','| --- | ---: | ---: |',
    ...c.rules.map(r=>'| '+r.ruleId+' — '+r.title+' | '+r.before+' | '+r.after+' |'),
    '', '> '+c.notice,''].join('\n');
}
export function writeJson(file, object) {fs.mkdirSync(path.dirname(path.resolve(file)),{recursive:true});fs.writeFileSync(file,JSON.stringify(object,null,2)+'\n');}
