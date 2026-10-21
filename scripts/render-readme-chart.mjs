#!/usr/bin/env node
/** Reproducible visualization of synthetic FEA demo findings, no network/dependencies. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const input=path.join(root,'demo/generated/reports/comparison/comparison.json');
const output=path.join(root,'assets/fea-demo-exposure.svg');
if(!fs.existsSync(input)) throw Error('Generate the synthetic demo first: npm run demo && npm run demo:check');
const data=JSON.parse(fs.readFileSync(input,'utf8'));
if(!Array.isArray(data.rules)||data.rules.length<5) throw Error('Expected at least 5 demo rules');
const asInt=v=>{if(!Number.isSafeInteger(v)||v<0)throw Error('Unexpected demo count');return v;};
const before=asInt(data.beforeCount),after=asInt(data.afterCount);
if(before!==data.rules.reduce((s,r)=>s+asInt(r.before),0)||after!==data.rules.reduce((s,r)=>s+asInt(r.after),0))throw Error('Rule totals do not match report');
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&','<':'<','>':'>','"':'"',"'":'''}[c]));
const names={'FEA001':'Source maps','FEA002':'Private key markers','FEA003':'Internal config','FEA004':'Debug artifacts','FEA005':'Test/dev assets','FEA006':'Client auth','FEA007':'Hardcoded secrets','FEA008':'Unobfuscated logic','FEA009':'Client data exposure'};
const rows=data.rules.map((r,i)=>{
  const y=249+i*48;
  const width=asInt(r.before)*80;
  const widthAfter=asInt(r.after)*80;
  return `<text x="48" y="${y+7}" font-size="14" font-weight="600" fill="#d8e6e7">${esc(names[r.ruleId]??r.ruleId)}</text>
    <rect x="278" y="${y-10}" width="${80*4}" height="16" rx="5" fill="#203944"/>
    <rect x="278" y="${y-10}" width="${width}" height="16" rx="5" fill="#f48b77"/>
    <rect x="278" y="${y+10}" width="${widthAfter}" height="6" rx="4" fill="#5cdec2"/>
    <text x="${Math.max(278+width+10,290)}" y="${y+5}" fill="#ffe1d9" font-size="13" font-weight="700">${r.before}</text>
    <text x="630" y="${y+5}" fill="#78e4cc" font-size="14" font-weight="700">→ ${r.after}</text>`;
}).join('\n');
const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="${310+data.rules.length*48}" viewBox="0 0 1000 ${310+data.rules.length*48}" role="img" aria-labelledby="title desc">
<title id="title">FEA synthetic Electron demo, before versus after security hygiene</title>
<desc id="desc">Findings fall from ${before} in the deliberately vulnerable baseline to ${after} in the improved fixture, across ${data.rules.length} checked release-risk categories. This is not a reverse-engineering resistance score.</desc>
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#0b1d28"/><stop offset="1" stop-color="#122f37"/></linearGradient><linearGradient id="a" x2="1"><stop stop-color="#65f2d3"/><stop offset="1" stop-color="#28bfa2"/></linearGradient></defs>
<rect width="1000" height="${310+data.rules.length*48}" rx="28" fill="url(#bg)"/>
<text x="48" y="57" font-size="15" font-weight="700" letter-spacing="3" fill="#78e4cc">VERIFIABLE DEMO DATA</text>
<text x="48" y="100" font-size="29" font-weight="750" fill="#f3fafb">Release exposure: before / after</text>
<text x="48" y="132" font-size="14" fill="#acc1c6">Deliberately vulnerable Electron test fixture · local resource scan</text>
<rect x="48" y="155" width="272" height="70" rx="14" fill="#243a43"/>
<text x="67" y="184" font-size="13" fill="#e5b0a3">Baseline findings</text>
<text x="67" y="212" font-size="32" font-weight="750" fill="#f48b77">${before}</text>
<path d="M341 187 L390 187" stroke="#75dcca" stroke-width="3"/><path d="M380 179 L392 187 L380 195" fill="none" stroke="#75dcca" stroke-width="3"/>
<rect x="411" y="155" width="272" height="70" rx="14" fill="#183d41"/>
<text x="430" y="184" font-size="13" fill="#abe4d6">Improved fixture</text>
<text x="430" y="212" font-size="32" font-weight="750" fill="#66e5cb">${after}</text>
<text x="48" y="247" font-size="1" fill="#fff"> </text>
${rows}
<line x1="48" x2="952" y1="${250+data.rules.length*48}" y2="${250+data.rules.length*48}" stroke="#38515a"/>
<text x="48" y="${277+data.rules.length*48}" font-size="13" fill="#9fb8bd">Source: demo/generated/reports/comparison/comparison.json</text>
<text x="48" y="${296+data.rules.length*48}" font-size="12" fill="#91aeb4">${before} → ${after} describes discovered synthetic release findings, NOT inability to reverse engineer code.</text>
</svg>`;
fs.writeFileSync(output,svg+'\n','utf8');
console.log('Rendered '+path.relative(root,output)+' from checked demo JSON');
