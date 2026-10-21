import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
const cli='src/cli.mjs';
const reports='demo/generated/reports';
if(!fs.existsSync(path.join(reports,'baseline','report.json')) || !fs.existsSync(path.join(reports,'hardened','report.json')))
  throw Error('Run npm run demo && npm run demo:check first');
for(const stage of ['baseline','hardened']) {
  const out=path.join(reports,stage,'findings.sarif');
  const r=spawnSync(process.execPath,[cli,'sarif',path.join(reports,stage,'report.json'),'--out',out],{encoding:'utf8'});
  if(r.status!==0)throw Error(`SARIF CLI ${stage}: ${r.stderr}`);
  const sarif=JSON.parse(fs.readFileSync(out,'utf8'));
  const expected=JSON.parse(fs.readFileSync(path.join(reports,stage,'report.json'),'utf8')).findings.length;
  if(sarif.runs[0].results.length!==expected)throw Error(`SARIF ${stage} findings mismatch`);
  for(const item of sarif.runs[0].results)if(item.locations[0].physicalLocation.artifactLocation.uri!=='.github/fea-sarif-anchor.md')throw Error('Location was not redacted');
}
console.log('SARIF DEMO PASS: synthetic sample findings match scanner report; GitHub anchor only; no private paths.');
