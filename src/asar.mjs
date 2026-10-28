import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {RULES, VERSION, inspectAsset, validateConfig} from './core.mjs';

const sha = data => crypto.createHash('sha256').update(data).digest('hex');
const MAX_HEADER_BYTES = 4*1024*1024;
const MAX_DEPTH = 48;

// Validate keys of every JSON object, unlike JSON.parse which silently accepts duplicates.
// The JSON grammar is checked by JSON.parse first; this tokenizer only checks key uniqueness.
export function parseUniqueJson(json) {
  const parsed=JSON.parse(json);
  const tokens=json.match(/"(?:\\\\.|[^"\\\\])*"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|\s+/g);
  if (!tokens || tokens.join('')!==json) throw Error('INVALID_JSON_TOKENS');
  let at=0;
  const next=()=>{while(at<tokens.length && /^\s+$/.test(tokens[at]))at++;return tokens[at];};
  const pop=()=>{const t=next();at++;return t;};
  function value(depth) {
    if(depth>MAX_DEPTH) throw Error('JSON_DEPTH_LIMIT');
    const token=pop();
    if(token==='{') {
      const keys=new Set();
      if(next()==='}') {pop();return;}
      while(true){
        const k=pop();if(!k?.startsWith('"'))throw Error('INVALID_JSON_KEY');
        const key=JSON.parse(k);if(keys.has(key))throw Error('DUPLICATE_JSON_KEY');keys.add(key);
        if(pop()!==':')throw Error('INVALID_JSON_COLON');
        value(depth+1);const sep=pop();if(sep==='}')break;if(sep!==',')throw Error('INVALID_JSON_OBJECT');
      }
    } else if(token==='[') {
      if(next()===']') {pop();return;}
      while(true){value(depth+1);const sep=pop();if(sep===']')break;if(sep!==',')throw Error('INVALID_JSON_ARRAY');}
    } else if(token===undefined || token==='}' || token===']'|| token===':')throw Error('INVALID_JSON_VALUE');
  }
  value(0);if(next()!==undefined)throw Error('TRAILING_JSON');
  return parsed;
}

function readExact(fd,length,position) {
  const b=Buffer.alloc(length);let n=0;
  while(n<length){const got=fs.readSync(fd,b,n,length-n,position+n);if(!got)throw Error('TRUNCATED_ASAR');n+=got;}
  return b;
}
const goodName = s => typeof s==='string' && s!=='' && s!=='.' && s!=='..' && !/[\\/\x00-\x1f]/.test(s) && !/^[a-z]:/i.test(s);

// Self-contained, read-only parser for regular ASAR files. Do not execute modules,
// follow links, or extract untrusted archive contents.
export function scanAsar(input,config,options={}) {
  validateConfig(config);
  const absolute=path.resolve(input);
  if(!absolute.toLowerCase().endsWith('.asar')) throw Error('Expected .asar file');
  if(options.out) {
    const output=path.resolve(options.out);
    if(output===absolute || output.startsWith(absolute+path.sep))throw Error('Output cannot overwrite archive');
  }
  const errors=[],findings=[],digests=[];
  let files=0,totalBytes=0,textFiles=0,opaqueFiles=0;
  const started=Date.now(),error=code=>{if(!errors.includes(code))errors.push(code);};
  let fd;
  try {
    if(fs.lstatSync(absolute).isSymbolicLink() || !fs.statSync(absolute).isFile()) throw Error('INPUT_NOT_REGULAR');
    fd=fs.openSync(absolute,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW||0));
    const stat=fs.fstatSync(fd);
    if(stat.size<16)throw Error('TRUNCATED_ASAR');
    const first=readExact(fd,8,0);
    if(first.readUInt32LE(0)!==4)throw Error('ASAR_PICKLE_INVALID');
    const pickleSize=first.readUInt32LE(4);
    if(pickleSize<12 || pickleSize>MAX_HEADER_BYTES || 8+pickleSize>stat.size)throw Error('ASAR_HEADER_SIZE_INVALID');
    const header=readExact(fd,pickleSize,8);
    const payloadLength=header.readUInt32LE(0);
    if(payloadLength!==pickleSize-4 || payloadLength<8 || payloadLength%4!==0)throw Error('ASAR_HEADER_PICKLE_INVALID');
    const jsonLength=header.readUInt32LE(4);
    if(jsonLength<2 || 8+jsonLength>pickleSize)throw Error('ASAR_JSON_LENGTH_INVALID');
    const decoded=new TextDecoder('utf-8',{fatal:true}).decode(header.subarray(8,8+jsonLength));
    const top=parseUniqueJson(decoded);
    if(!top || typeof top!=='object' || Array.isArray(top) || !top.files || typeof top.files!=='object'||Array.isArray(top.files))throw Error('ASAR_TREE_INVALID');
    const dataStart=8+pickleSize;
    const unpackBase=absolute+'.unpacked';
    function visit(entries,parts=[],depth=0){
      if(depth>MAX_DEPTH){error('ASAR_DEPTH_LIMIT');return;}
      for(const name of Object.keys(entries).sort()){
        if(errors.length)return;
        if(Date.now()-started>config.limits.maxDurationMs){error('TIME_LIMIT');return;}
        if(!goodName(name)){error('ASAR_PATH_INVALID');return;}
        const record=entries[name],segs=[...parts,name],relative=segs.join('/');
        if(!record || typeof record!=='object' || Array.isArray(record)){error('ASAR_ENTRY_INVALID');return;}
        if(Object.hasOwn(record,'link')){error('ASAR_LINK_UNSUPPORTED');return;}
        if(Object.hasOwn(record,'files')){
          if(!record.files || typeof record.files!=='object'||Array.isArray(record.files)){error('ASAR_DIRECTORY_INVALID');return;}
          visit(record.files,segs,depth+1);continue;
        }
        if(!Number.isSafeInteger(record.size)||record.size<0){error('ASAR_FILE_SIZE_INVALID');return;}
        if(++files>config.limits.maxFiles){error('FILE_LIMIT');return;}
        totalBytes+=record.size;
        if(totalBytes>config.limits.maxTotalBytes){error('TOTAL_BYTE_LIMIT');return;}
        if(record.size>config.limits.maxFileBytes){error('FILE_BYTE_LIMIT');return;}
        let bytes;
        if(record.unpacked===true){
          // Reject symlinks in every path component of the sidecar hierarchy.
          let cursor=unpackBase;
          for(const segment of segs){
            if(fs.lstatSync(cursor).isSymbolicLink()) throw Error('UNPACKED_SYMLINK');
            cursor=path.join(cursor,segment);
          }
          if(fs.lstatSync(cursor).isSymbolicLink() || !fs.statSync(cursor).isFile())throw Error('UNPACKED_FILE_INVALID');
          if(fs.statSync(cursor).size!==record.size)throw Error('UNPACKED_SIZE_MISMATCH');
          bytes=fs.readFileSync(cursor);
        } else {
          if(typeof record.offset!=='string'|| !/^(0|[1-9]\d*)$/.test(record.offset)) {error('ASAR_OFFSET_INVALID');return;}
          const position=BigInt(record.offset)+BigInt(dataStart),size=BigInt(record.size);
          if(position+size>BigInt(stat.size)||position>BigInt(Number.MAX_SAFE_INTEGER)){error('ASAR_BOUNDS_INVALID');return;}
          bytes=readExact(fd,record.size,Number(position));
        }
        if(record.integrity) {
          if(record.integrity.algorithm!=='SHA256' || !/^[0-9a-f]{64}$/i.test(record.integrity.hash||'') ||
              sha(bytes)!==record.integrity.hash.toLowerCase()){error('ASAR_INTEGRITY_MISMATCH');return;}
        }
        const assessment=inspectAsset(relative,bytes);
        if(assessment.textInspected)textFiles++;
        if(assessment.opaqueText){opaqueFiles++;error('OPAQUE_TEXT');return;}
        const pathId=sha(relative).slice(0,16);
        for(const ruleId of assessment.ruleIds)findings.push({ruleId,severity:RULES[ruleId].severity,pathId,
          fingerprint:sha(ruleId+':'+pathId).slice(0,20),message:RULES[ruleId].title});
        digests.push(sha(relative)+':'+sha(bytes));
      }
    }
    visit(top.files);
    if(fs.fstatSync(fd).size!==stat.size || fs.fstatSync(fd).mtimeMs!==stat.mtimeMs)error('INPUT_CHANGED');
  } catch(e) {error('ASAR_PARSE_OR_READ_ERROR');} finally {if(fd!==undefined)fs.closeSync(fd);}
  return {
    formatVersion:1,scannerVersion:VERSION,profile:'electron-resources',artifactType:'asar',inputStage:config.inputStage,
    generatedAt:new Date().toISOString(),inputDigest:sha(digests.sort().join('\n')),
    coverage:{complete:errors.length===0,ruleIds:Object.keys(RULES),scannedFiles:files,inspectedTextFiles:textFiles,
      opaqueFiles,errors:errors.sort(),adapter:'asar-readonly-v1'},
    findings:findings.sort((a,b)=>a.ruleId.localeCompare(b.ruleId)||a.pathId.localeCompare(b.pathId))
  };
}
