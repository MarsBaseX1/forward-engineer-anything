import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createMcpHandler} from '../src/mcp.mjs';
import {DEFAULT_CONFIG,scanDirectory} from '../src/core.mjs';
function setup(t){
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'fea-mcp-'));t.after(()=>fs.rmSync(tmp,{recursive:true,force:true}));
 const input=path.join(tmp,'app'),report=path.join(tmp,'report.json'),policy=path.join(tmp,'fea.json');
 fs.mkdirSync(input);fs.writeFileSync(path.join(input,'internal-secret.js'),'const x="SENSITIVE_DO_NOT_SHARE";\n-----BEGIN PRIVATE KEY-----');
 fs.writeFileSync(report,JSON.stringify(scanDirectory(input,DEFAULT_CONFIG)));fs.writeFileSync(policy,JSON.stringify(DEFAULT_CONFIG));
 return {tmp,report,policy};
}
const call=(id,method,params)=>({jsonrpc:'2.0',id,method,params});
test('MCP read-only tools expose redacted summaries and policy status',t=>{
 const {report,policy}=setup(t),h=createMcpHandler({reportFile:report,policyFile:policy});
 assert.equal(h(call(1,'tools/list',{})).error.code,-32000);
 assert.equal(h(call(2,'initialize',{protocolVersion:'2025-11-25'})).result.protocolVersion,'2025-11-25');
 assert.equal(h({jsonrpc:'2.0',method:'notifications/initialized'}),null);
 assert.deepEqual(h(call(3,'tools/list',{})).result.tools.map(x=>x.name),['fea_report_summary','fea_list_findings','fea_policy_check']);
 const summary=h(call(4,'tools/call',{name:'fea_report_summary',arguments:{}})).result;
 assert.ok(summary.structuredContent.findings>=1);
 assert.equal(JSON.stringify(summary).includes('SENSITIVE_DO_NOT_SHARE'),false);
 const findings=h(call(5,'tools/call',{name:'fea_list_findings',arguments:{limit:10}})).result;
 assert.ok(findings.structuredContent.findings.length>=1);
 assert.equal(JSON.stringify(findings).includes('internal-secret.js'),false);
 assert.equal(h(call(6,'tools/call',{name:'fea_policy_check',arguments:{}})).result.structuredContent.ok,false);
 assert.equal(h(call(7,'tools/call',{name:'fea_list_findings',arguments:{limit:101}})).error.code,-32602);
 assert.equal(h(call(8,'tools/call',{name:'fea_report_summary',arguments:{path:'/etc/passwd'}})).error.code,-32602);
 assert.equal(h(call(9,'tools/call',{name:'not_a_tool',arguments:{}})).error.code,-32602);
});
test('MCP rejects symlink report and unsupported report shapes',t=>{
 const {tmp,report,policy}=setup(t);
 fs.writeFileSync(report,'{"findings":[]}');assert.throws(()=>createMcpHandler({reportFile:report,policyFile:policy}),/MCP_REPORT_FORMAT/);
 const link=path.join(tmp,'link.json');
 try{fs.symlinkSync(report,link);}catch(e){if(e.code==='EPERM'||e.code==='EACCES')return;throw e;}
 assert.throws(()=>createMcpHandler({reportFile:link,policyFile:policy}),/MCP_REPORT_UNSUPPORTED/);
});
test('MCP stdio protocol works end-to-end without writing to stdout except JSON-RPC',async t=>{
 const {report,policy}=setup(t);
 const child=spawn(process.execPath,['src/mcp.mjs','--report',report,'--policy',policy],{cwd:path.resolve(''),stdio:['pipe','pipe','pipe']});
 t.after(()=>child.kill());
 let output='';child.stdout.setEncoding('utf8');child.stdout.on('data',v=>output+=v);
 child.stdin.write(JSON.stringify(call(1,'initialize',{protocolVersion:'2025-11-25'}))+'\n');
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
 child.stdin.write(JSON.stringify(call(2,'tools/list',{}))+'\n');child.stdin.end();
 await new Promise((resolve,reject)=>{child.once('exit',c=>c===0?resolve():reject(Error('exit='+c)));child.once('error',reject)});
 const msgs=output.trim().split('\n').map(JSON.parse);
 assert.equal(msgs.length,2);assert.equal(msgs[1].result.tools.length,3);
});
