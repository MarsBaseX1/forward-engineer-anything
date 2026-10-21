import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
const node=process.execPath, cli='src/cli.mjs';
function execute(args,code=0) {
  const r=spawnSync(node,[cli,...args],{encoding:'utf8'});
  if(r.status!==code)throw Error('Failed: fea '+args.join(' ')+'\n'+r.stdout+'\n'+r.stderr);
}
execute(['scan','demo/generated/baseline/app','--config','.fea.json','--out','demo/generated/reports/baseline']);
execute(['scan','demo/generated/hardened/app','--config','.fea.json','--out','demo/generated/reports/hardened']);
execute(['verify','demo/generated/reports/baseline/report.json','--policy','.fea.json'],2);
execute(['verify','demo/generated/reports/hardened/report.json','--policy','.fea.json']);
execute(['compare','demo/generated/reports/baseline/report.json','demo/generated/reports/hardened/report.json','--out','demo/generated/reports/comparison']);
execute(['asar-scan','demo/generated/baseline/app.asar','--config','.fea.json','--out','demo/generated/reports/asar-baseline']);
execute(['asar-scan','demo/generated/hardened/app.asar','--config','.fea.json','--out','demo/generated/reports/asar-hardened']);
execute(['verify','demo/generated/reports/asar-baseline/report.json','--policy','.fea.json'],2);
execute(['verify','demo/generated/reports/asar-hardened/report.json','--policy','.fea.json']);
execute(['compare','demo/generated/reports/asar-baseline/report.json','demo/generated/reports/asar-hardened/report.json','--out','demo/generated/reports/asar-comparison']);
const ac=JSON.parse(readFileSync('demo/generated/reports/asar-comparison/comparison.json'));
if(ac.beforeCount<5 || ac.afterCount!==0 || ac.resolved<5)throw Error('ASAR demonstration comparison mismatch');
const c=JSON.parse(readFileSync('demo/generated/reports/comparison/comparison.json'));
if(c.beforeCount<5 || c.afterCount!==0 || c.resolved<5 || c.introduced!==0)throw Error('Demonstration comparison did not match expected result');
console.log('DEMO PASS: raw resources and ASAR: baseline blocked, hardened passed; findings resolved: '+c.resolved);
