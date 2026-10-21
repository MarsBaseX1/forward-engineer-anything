#!/usr/bin/env node
import fs from 'node:fs';
import readline from 'node:readline';
import {fileURLToPath} from 'node:url';
import {readConfig, verifyReport, RULES} from './core.mjs';

// MCP only serves a precomputed report selected by the operator at startup.
// There is deliberately no tool to open arbitrary paths, execute code, or update data.
export const PROTOCOL='2025-11-25';
const MAX_REPORT=4_000_000;
const cappedText=(s,n=80)=>typeof s==='string'?s.slice(0,n):'';
function loadSafeReport(filename){
  const stat=fs.lstatSync(filename);
  if(!stat.isFile() || stat.isSymbolicLink() || stat.size>MAX_REPORT)throw Error('MCP_REPORT_UNSUPPORTED');
  const raw=JSON.parse(fs.readFileSync(filename,'utf8'));
  if(!raw || !raw.coverage || typeof raw.coverage.complete!=='boolean' || !Array.isArray(raw.findings) || raw.findings.length>20000)throw Error('MCP_REPORT_FORMAT');
  // Protect the MCP channel: never expose source contents, raw file paths or custom messages.
  const findings=raw.findings.map(f=>{
    if(!RULES[f.ruleId] || !/^[a-f0-9]{16}$/.test(f.pathId??''))throw Error('MCP_FINDING_FORMAT');
    return {ruleId:f.ruleId,severity:RULES[f.ruleId].severity,pathId:f.pathId};
  });
  return {raw,findings};
}
export const MCP_TOOLS=[
  {name:'fea_report_summary',description:'Return a bounded overview of the operator-selected, precomputed FEA scan report. Read-only; no raw paths or secrets.',inputSchema:{type:'object',additionalProperties:false}},
  {name:'fea_list_findings',description:'List sanitized rule IDs, severity, and hashed path IDs from the precomputed report.',inputSchema:{type:'object',properties:{ruleId:{type:'string',enum:Object.keys(RULES)},limit:{type:'integer',minimum:1,maximum:100}},additionalProperties:false}},
  {name:'fea_policy_check',description:'Apply the operator-selected FEA policy to the precomputed report. No tool-supplied file paths.',inputSchema:{type:'object',additionalProperties:false}}
];
const err=(id,code,message)=>({jsonrpc:'2.0',id,error:{code,message}});
const success=(id,result)=>({jsonrpc:'2.0',id,result});
const toolResult=(data)=>({content:[{type:'text',text:JSON.stringify(data)}],structuredContent:data});
function permitted(args,allowed){return args && typeof args==='object' && !Array.isArray(args) && Object.keys(args).every(k=>allowed.includes(k));}
export function createMcpHandler({reportFile,policyFile}){
  if(typeof reportFile!=='string' || !reportFile)throw Error('MCP_REPORT_REQUIRED');
  if(typeof policyFile!=='string' || !policyFile)throw Error('MCP_POLICY_REQUIRED');
  const report=loadSafeReport(reportFile),policy=readConfig(policyFile);
  let initialized=false, ready=false;
  return function handle(msg){
    if(!msg || msg.jsonrpc!=='2.0' || typeof msg.method!=='string')return err(msg?.id??null,-32600,'Invalid JSON-RPC request');
    if(!Object.hasOwn(msg,'id')){
      if(msg.method==='notifications/initialized' && initialized)ready=true;
      return null;
    }
    if(!Number.isSafeInteger(msg.id) && typeof msg.id!=='string')return err(null,-32600,'Invalid request ID');
    const id=msg.id;
    if(msg.method==='initialize'){
      if(!msg.params || typeof msg.params.protocolVersion!=='string')return err(id,-32602,'Invalid initialize parameters');
      if(!['2025-11-25','2025-06-18'].includes(msg.params.protocolVersion))return err(id,-32602,'Unsupported MCP protocol version');
      initialized=true;
      return success(id,{protocolVersion:msg.params.protocolVersion,capabilities:{tools:{}},serverInfo:{name:'fea-audit-readonly',version:'0.3.2-alpha.1'},instructions:'Only reads an operator-selected FEA report. Sanitized findings are not proof of security.'});
    }
    if(msg.method==='ping')return success(id,{});
    if(!initialized || !ready)return err(id,-32000,'MCP initialization required');
    if(msg.method==='tools/list')return success(id,{tools:MCP_TOOLS});
    if(msg.method!=='tools/call')return err(id,-32601,'Unknown method');
    const name=msg.params?.name,args=msg.params?.arguments??{};
    if(!MCP_TOOLS.some(t=>t.name===name))return err(id,-32602,'Unknown tool');
    if(!permitted(args,name==='fea_list_findings'?['ruleId','limit']:[]))return err(id,-32602,'Invalid tool arguments');
    if(name==='fea_report_summary'){
      const counts=Object.fromEntries(Object.keys(RULES).map(k=>[k,report.findings.filter(f=>f.ruleId===k).length]));
      return success(id,toolResult({complete:report.raw.coverage.complete,findings:report.findings.length,counts,stage:cappedText(report.raw.inputStage,32),coverageErrors:Array.isArray(report.raw.coverage.errors)?report.raw.coverage.errors.length:0,notice:'Sanitized precomputed report; not a complete security guarantee.'}));
    }
    if(name==='fea_list_findings'){
      if(args.ruleId!==undefined && !Object.hasOwn(RULES,args.ruleId))return err(id,-32602,'Invalid ruleId');
      if(args.limit!==undefined && (!Number.isSafeInteger(args.limit)||args.limit<1||args.limit>100))return err(id,-32602,'Invalid limit');
      const filtered=report.findings.filter(f=>!args.ruleId||f.ruleId===args.ruleId);
      return success(id,toolResult({total:filtered.length,findings:filtered.slice(0,args.limit??50),truncated:filtered.length>(args.limit??50)}));
    }
    const status=verifyReport(report.raw,policy);
    return success(id,toolResult({ok:status.ok,blockedCount:status.blockedCount,problems:Array.isArray(status.problems)?status.problems.map(s=>cappedText(s,80)).slice(0,20):[],notice:'Policy check uses operator-selected trusted files only; it is not an attestation.'}));
  };
}
export function startStdio({reportFile,policyFile,input=process.stdin,output=process.stdout}){
  const handler=createMcpHandler({reportFile,policyFile});
  const rl=readline.createInterface({input,crlfDelay:Infinity});
  rl.on('line',line=>{
    if(Buffer.byteLength(line,'utf8')>262144){output.write(JSON.stringify(err(null,-32700,'Message too large'))+'\n');return;}
    let request;
    try{request=JSON.parse(line);}catch{output.write(JSON.stringify(err(null,-32700,'Parse error'))+'\n');return;}
    let response;
    try{response=handler(request);}catch{response=err(request?.id??null,-32603,'Internal server error');}
    if(response)output.write(JSON.stringify(response)+'\n');
  });
  return rl;
}
if(process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1]){
  const a=process.argv.slice(2),r=a.indexOf('--report'),p=a.indexOf('--policy');
  if(r<0||p<0||!a[r+1]||!a[p+1]){console.error('Usage: node src/mcp.mjs --report <trusted-report.json> --policy <trusted-fea.json>');process.exitCode=1;}
  else{try{startStdio({reportFile:a[r+1],policyFile:a[p+1]});}catch(e){console.error('FEA MCP startup failed: '+e.message);process.exitCode=1;}}
}
