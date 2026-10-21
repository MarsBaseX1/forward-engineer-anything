import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyPackagedFixture} from '../src/real-package.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const fixtureDir=path.join(root,'demo','real-electron-app');
const outDir=path.join(fixtureDir,'out');
const reportDir=path.join(root,'demo','generated','reports','real-electron',process.platform);
try{
  const report=await verifyPackagedFixture({outDir,fixtureDir,reportDir,platform:process.platform});
  console.log('REAL ELECTRON PASS',JSON.stringify({platform:report.platform,checks:report.checks}));
}catch(e){console.error('REAL ELECTRON FAIL',e.message);process.exitCode=1;}
