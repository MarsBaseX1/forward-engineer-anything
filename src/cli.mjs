#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {scanAsar} from './asar.mjs';
import {toSarif} from './sarif.mjs';
import {planForge} from './protect.mjs';
import {previewHardening,applyHardening,rollbackHardening} from './protect-apply.mjs';
import {verifyAuthenticode} from './signature.mjs';
import {evaluateFuseCompatibility,inspectUnpackedRelease} from './release-readiness.mjs';
import {loadArenaJson,compareArena,arenaMarkdown} from './arena.mjs';
import {importExternalFiles} from './arena-import.mjs';
import {runPairedArena} from './arena-runner.mjs';
import {generateMigrationSuggestions,migrationMarkdown} from './migrate-suggestions.mjs';
import {generateObfuscationSuggestions,obfuscationMarkdown} from './obfuscation-suggestions.mjs';
import {DEFAULT_CONFIG,VERSION,readConfig,scanDirectory,verifyReport,compareReports,comparisonMarkdown,writeJson} from './core.mjs';

const help=`FEA ${VERSION} — Electron release-resource security checks (experimental)
Usage:
  fea init --profile electron-resources [--out .fea.json]
  fea scan <resources-dir> --config .fea.json --out <report-dir>
  fea verify <report.json> --policy .fea.json
  fea sarif <trusted-report.json> --out <results.sarif>
  fea compare <before.json> <after.json> --out <comparison-dir>
  fea asar-scan <app.asar> --config .fea.json --out <report-dir>
  fea plan <electron-forge-project> --out <plan-dir>
  fea protect preview <project-dir> --out <plan.json>
  fea protect apply <project-dir> --plan <plan.json> --state <external-backups-dir>
  fea protect rollback <project-dir> --receipt <receipt.json>
  fea signature <file.exe> --out <report-dir> [--thumbprint SHA1HEX]
  fea release compat <project-dir> --platform win32|darwin --out <report.json>
  fea release inspect <unpacked-root> --platform win32|darwin --config .fea.json --out <report-dir> [--asar-sha256 SHA256]
  fea migrate <trusted-report.json> --out <suggestions-dir>
  fea obfuscate <trusted-report.json> --out <suggestions-dir>
  fea arena compare <baseline-run.json> <hardened-run.json> --suite <suite.json> --out <report-dir>
  fea arena import <trials.jsonl> --suite <suite.json> --descriptor <descriptor.json> --out <run.json>
  fea arena execute --suite <suite.json> --baseline <app.asar> --hardened <app.asar> --adapter <trusted.mjs> --engine <engine.json> --out <dir> --i-own-artifacts
Exit codes: 0 success, 2 policy/coverage failure, 1 invalid input or error.
IMPORTANT: scans are bounded and format-specific, not installer extraction or proof of security.
`;
function parse(argv) {
  const positional=[], flags={};
  for(let i=0;i<argv.length;i++) {
    const arg=argv[i];
    if(arg.startsWith('--')) {
      const name=arg.slice(2);
      if(!['out','config','policy','profile','thumbprint','suite','descriptor','baseline','hardened','adapter','engine','i-own-artifacts','plan','state','receipt','platform','asar-sha256','help'].includes(name) || Object.hasOwn(flags,name))throw Error('Invalid flag: '+arg);
      if(name==='help'||name==='i-own-artifacts'){flags[name]=true;continue;}
      if(!argv[i+1] || argv[i+1].startsWith('--')) throw Error('Missing value for '+arg);
      flags[name]=argv[++i];
    } else positional.push(arg);
  }
  return {positional,flags};
}
function reportSummary(report) {
  return `FEA scan — ${report.coverage.complete?'complete':'INCOMPLETE'}\nInput stage: ${report.inputStage}\nFiles: ${report.coverage.scannedFiles}\nFindings: ${report.findings.length}\n${report.findings.map(f=>f.ruleId+' '+f.pathId+' ('+f.severity+')').join('\n')}\n${report.coverage.errors.length?'Coverage errors: '+report.coverage.errors.join(', '):''}\nNote: path IDs are hashed; reports contain no raw paths or secret values.\n`;
}
export function run(args) {
  const [command,...rest]=args;
  if(!command || command==='--help' || command==='help') {process.stdout.write(help);return 0;}
  const {positional,flags}=parse(rest);
  if(flags.help) {process.stdout.write(help);return 0;}
  switch(command) {
    case 'init': {
      if(positional.length || flags.profile && flags.profile!=='electron-resources') throw Error('Only electron-resources profile is supported');
      const filename=flags.out || '.fea.json';
      if(fs.existsSync(filename))throw Error('Refusing to overwrite config: '+filename);
      writeJson(filename,DEFAULT_CONFIG);
      console.log('Created '+filename);
      return 0;
    }
    case 'scan': {
      if(positional.length!==1 || !flags.out)throw Error('scan requires <resources-dir> and --out');
      const config=readConfig(flags.config || '.fea.json');
      const report=scanDirectory(positional[0],config,{out:flags.out});
      writeJson(path.join(flags.out,'report.json'),report);
      fs.writeFileSync(path.join(flags.out,'summary.txt'),reportSummary(report));
      console.log(reportSummary(report));
      return report.coverage.complete?0:2;
    }
    case 'asar-scan': {
      if (positional.length!==1 || !flags.out) throw Error('asar-scan requires <app.asar> --out');
      const config = readConfig(flags.config || '.fea.json');
      const report = scanAsar(positional[0],config,{out:flags.out});
      writeJson(path.join(flags.out,'report.json'),report);
      fs.writeFileSync(path.join(flags.out,'summary.txt'),reportSummary(report));
      console.log(reportSummary(report));
      return report.coverage.complete?0:2;
    }
    case 'sarif': {
      if(positional.length!==1 || !flags.out || !flags.out.toLowerCase().endsWith('.sarif')) throw Error('sarif requires <trusted-report.json> --out <file.sarif>');
      const report=JSON.parse(fs.readFileSync(positional[0],'utf8'));
      const result=toSarif(report);
      writeJson(flags.out,result);
      console.log(`Wrote sanitized SARIF: ${result.runs[0].results.length} finding(s), physical locations point to .github/fea-sarif-anchor.md (NOT actual asset paths)`);
      return 0;
    }
    case 'plan': {
      if(positional.length!==1 || !flags.out) throw Error('plan requires <project-dir> --out');
      const plan=planForge(positional[0]);
      writeJson(path.join(flags.out,'plan.json'),plan);
      console.log('Wrote review-only plan: '+path.join(flags.out,'plan.json'));
      return plan.supported?0:2;
    }
    case 'protect': {
      const [operation,project]=positional;
      if(positional.length!==2)throw Error('protect requires preview/apply/rollback and project directory');
      if(operation==='preview'){
        if(!flags.out)throw Error('protect preview requires --out <plan.json>');
        const result=previewHardening(project);
        writeJson(flags.out,result);
        console.log('Wrote reviewable, metadata-only Forge plan: '+flags.out);
        return 0;
      }
      if(operation==='apply'){
        if(!flags.plan||!flags.state)throw Error('protect apply requires --plan and external --state');
        const plan=JSON.parse(fs.readFileSync(flags.plan,'utf8'));
        const result=applyHardening(project,plan,flags.state);
        console.log('Applied a bounded JSON setting change; receipt: '+result.receipt);
        return 0;
      }
      if(operation==='rollback'){
        if(!flags.receipt)throw Error('protect rollback requires --receipt');
        const result=rollbackHardening(project,flags.receipt);
        console.log('Restored original config: '+result.configFile);
        return 0;
      }
      throw Error('protect supports preview, apply, rollback');
    }
    case 'release': {
      if(positional.length!==2 || !flags.platform || !flags.out)throw Error('release requires compat/inspect <path> --platform win32|darwin --out');
      const [operation,location]=positional;
      if(operation==='compat'){
        const report=evaluateFuseCompatibility(location,flags.platform);
        writeJson(flags.out,report);
        console.log('Fuse compatibility: '+report.status+' (declared versions only; no binary fuse verification)');
        return report.status==='compatible-declarations'?0:2;
      }
      if(operation==='inspect'){
        const config=readConfig(flags.config||'.fea.json');
        const {result,scan}=inspectUnpackedRelease(location,{platform:flags.platform,config,expectedAsarSha256:flags['asar-sha256'],out:flags.out});
        writeJson(path.join(flags.out,'release.json'),result);
        writeJson(path.join(flags.out,'asar-report.json'),scan);
        console.log('Release static inspection: '+result.status+'; not a signature, binary fuse, or GUI runtime verification.');
        return result.status==='static-checks-pass'?0:2;
      }
      throw Error('release supports compat and inspect');
    }
    case 'migrate': {
      if(positional.length!==1 || !flags.out)throw Error('migrate requires <trusted-report.json> --out');
      const report=JSON.parse(fs.readFileSync(positional[0],'utf8'));
      const result=generateMigrationSuggestions(report);
      writeJson(path.join(flags.out,'suggestions.json'),result);
      fs.writeFileSync(path.join(flags.out,'suggestions.md'),migrationMarkdown(result));
      console.log('Wrote migration suggestions: '+path.join(flags.out,'suggestions.md'));
      return 0;
    }
    case 'obfuscate': {
      if(positional.length!==1 || !flags.out)throw Error('obfuscate requires <trusted-report.json> --out');
      const report=JSON.parse(fs.readFileSync(positional[0],'utf8'));
      const result=generateObfuscationSuggestions(report);
      writeJson(path.join(flags.out,'obfuscation.json'),result);
      fs.writeFileSync(path.join(flags.out,'obfuscation.md'),obfuscationMarkdown(result));
      console.log('Wrote obfuscation suggestions: '+path.join(flags.out,'obfuscation.md'));
      return 0;
    }
    case 'signature': {
      if(positional.length!==1 || !flags.out) throw Error('signature requires <file.exe> --out');
      const report=verifyAuthenticode(positional[0],{expectedThumbprint:flags.thumbprint});
      writeJson(path.join(flags.out,'signature.json'),report);
      console.log('Authenticode: '+report.status+'; '+report.notice);
      return report.valid?0:2;
    }
    case 'arena': {
      if(positional[0]==='execute'){
        if(positional.length!==1 || !flags.suite || !flags.baseline || !flags.hardened || !flags.adapter || !flags.engine || !flags.out || !flags['i-own-artifacts'])
          throw Error('arena execute requires --suite, --baseline, --hardened, --adapter, --engine, --out and --i-own-artifacts');
        const result=runPairedArena({suite:loadArenaJson(flags.suite),baselineFile:flags.baseline,
          hardenedFile:flags.hardened,adapterFile:flags.adapter,engine:loadArenaJson(flags.engine),acknowledgeExecution:true});
        writeJson(path.join(flags.out,'baseline.json'),result.baseline);
        writeJson(path.join(flags.out,'hardened.json'),result.hardened);
        writeJson(path.join(flags.out,'comparison.json'),result.comparison);
        fs.writeFileSync(path.join(flags.out,'comparison.md'),arenaMarkdown(result.comparison));
        console.log('Executed trusted local adapter: outcomes self-reported; not proof of AI reverse-engineering resistance.');
        return 0;
      }
      if(positional[0]==='import'){
        if(positional.length!==2 || !flags.suite || !flags.descriptor || !flags.out)throw Error('arena import requires <trials.jsonl> --suite --descriptor --out');
        const run=importExternalFiles({trialsFile:positional[1],suiteFile:flags.suite,descriptorFile:flags.descriptor});
        writeJson(flags.out,run);
        console.log('Imported external self-reported run: evidence content NOT verified');
        return 0;
      }
      if(positional.length!==3 || positional[0]!=='compare' || !flags.suite || !flags.out)
        throw Error('arena compare requires 2 run files, --suite and --out');
      const suite=loadArenaJson(flags.suite);
      const result=compareArena(suite,loadArenaJson(positional[1]),loadArenaJson(positional[2]));
      writeJson(path.join(flags.out,'comparison.json'),result);
      fs.writeFileSync(path.join(flags.out,'comparison.md'),arenaMarkdown(result));
      console.log(arenaMarkdown(result));
      return 0;
    }
    case 'verify': {
      if(positional.length!==1)throw Error('verify requires a report.json');
      const config=readConfig(flags.policy || flags.config || '.fea.json');
      const result=verifyReport(JSON.parse(fs.readFileSync(positional[0],'utf8')),config);
      console.log(result.ok?'PASS: no blocking findings and complete coverage':'FAIL: '+result.blockedCount+' blocking finding(s); '+result.problems.join(', '));
      console.log(result.notice);
      return result.ok?0:2;
    }
    case 'compare': {
      if(positional.length!==2 || !flags.out)throw Error('compare requires <before.json> <after.json> --out');
      const c=compareReports(...positional.map(f=>JSON.parse(fs.readFileSync(f,'utf8'))));
      writeJson(path.join(flags.out,'comparison.json'),c);
      fs.mkdirSync(flags.out,{recursive:true});
      fs.writeFileSync(path.join(flags.out,'comparison.md'),comparisonMarkdown(c));
      console.log(comparisonMarkdown(c));
      return 0;
    }
    default: throw Error('Unknown command '+command+'\n'+help);
  }
}
try {process.exitCode=run(process.argv.slice(2));}
catch(err) {console.error('FEA error: '+err.message);process.exitCode=1;}
