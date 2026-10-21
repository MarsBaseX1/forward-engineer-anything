import {packDemoAsar} from './pack-asar.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const base=path.dirname(fileURLToPath(import.meta.url));
const app=path.join(base,'electron-app');
const output=path.join(base,'generated');
const write=(file,contents)=>{fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,contents);};
const source=fs.readFileSync(path.join(app,'main.cjs'),'utf8');
const html=fs.readFileSync(path.join(app,'index.html'),'utf8');
const pkg=fs.readFileSync(path.join(app,'package.json'),'utf8');
fs.rmSync(output,{recursive:true,force:true});
for(const kind of ['baseline','hardened']) {
  const target=path.join(output,kind,'app');
  write(path.join(target,'package.json'),pkg);
  write(path.join(target,'index.html'),html);
  write(path.join(target,'main.cjs'),source+(kind==='baseline'?'\n//# sourceMappingURL=main.cjs.map\n':''));
  if(kind==='baseline') {
    write(path.join(target,'main.cjs.map'),JSON.stringify({version:3,file:'main.cjs',sources:['main.cjs'],sourcesContent:[source],mappings:''}));
    write(path.join(target,'internal-config.json'),JSON.stringify({INTERNAL_API_URL:'https://example.invalid/internal'},null,2));
    write(path.join(target,'keys','demo.pem'),'-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n');
    write(path.join(target,'debug.pdb'),'Synthetic demonstration artifact. Not a real PDB.');
    write(path.join(target,'__tests__','smoke.test.js'),'// synthetic non-production fixture\n');
  }
  packDemoAsar(target,path.join(output,kind,'app.asar'));
}
console.log('Generated baseline and hardened runnable Electron resource trees under demo/generated/');
console.log('No user secrets or real private keys are included.');
