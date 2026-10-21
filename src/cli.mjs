#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {scanAsar} from './asar.mjs';
import {planForge} from './protect.mjs';
import {verifyAuthenticode} from './signature.mjs';
import {loadArenaJson,compareArena,arenaMarkdown} from './arena.mjs';
import {DEFAULT_CONFIG,VERSION,readConfig,scanDirectory,verifyReport,compareReports,comparisonMarkdown,writeJson} from './core.mjs';

const help=`FEA ${VERSION} — Electron release-resource security checks (experimental)
Usage:
  fea init --profile electron-resources [--out .fea.json]
  fea scan <resources-dir> --config .fea.json --out <report-dir>
  fea verify <report.json> --policy .fea.json
  fea compare <before.json> <after.json> --out <comparison-dir>
  fea asar-scan <app.asar> --config .fea.json --out <report-dir>
  fea plan <electron-forge-project> --out <plan-dir>
  fea signature <file.exe> --out <report-dir> [--thumbprint SHA1HEX]
  fea arena compare <baseline-run.json> <hardened-run.json> --suite <suite.json> --out <report-dir>
Exit codes: 0 success, 2 policy/coverage failure, 1 invalid input or error.
IMPORTANT: scans are bounded and format-specific, not installer extraction or proof of security.
`;
function parse(argv) {
  const positional=[], flags={};
  for(let i=0;i<argv.length;i++) {
    const arg=argv[i];
    if(arg.startsWith('--')) {
      const name=arg.slice(2);
      if(!['out','config','policy','profile','thumbprint','suite','help'].includes(name) || Object.hasOwn(flags,name))throw Error('Invalid flag: '+arg);
      if(name==='help'){flags.help=true;continue;}
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
    case 'plan': {
      if(positional.length!==1 || !flags.out) throw Error('plan requires <project-dir> --out');
      const plan=planForge(positional[0]);
      writeJson(path.join(flags.out,'plan.json'),plan);
      console.log('Wrote review-only plan: '+path.join(flags.out,'plan.json'));
      return plan.supported?0:2;
    }
    case 'signature': {
      if(positional.length!==1 || !flags.out) throw Error('signature requires <file.exe> --out');
      const report=verifyAuthenticode(positional[0],{expectedThumbprint:flags.thumbprint});
      writeJson(path.join(flags.out,'signature.json'),report);
      console.log('Authenticode: '+report.status+'; '+report.notice);
      return report.valid?0:2;
    }
    case 'arena': {
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
