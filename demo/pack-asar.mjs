// Minimal ASAR fixture writer for owned demo resources only; not production packager.
import fs from 'node:fs';
import path from 'node:path';
function list(root,folder=root) {
  const nodes={};
  for(const item of fs.readdirSync(folder,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
    const filename=path.join(folder,item.name);
    if(item.isDirectory())nodes[item.name]={files:list(root,filename)};
    else if(item.isFile())nodes[item.name]={file:filename};
    else throw Error('Demo fixture contains non-regular entry');
  }
  return nodes;
}
export function packDemoAsar(input,output) {
  const files=list(input), data=[];let offset=0;
  function visit(entries){for(const node of Object.values(entries)){
    if(node.files){visit(node.files);continue;}
    const content=fs.readFileSync(node.file);
    delete node.file;node.offset=String(offset);node.size=content.length;offset+=content.length;data.push(content);
  }}
  visit(files);
  const json=Buffer.from(JSON.stringify({files}),'utf8');
  const payloadLength=(4+json.length+3)&~3;
  const header=Buffer.alloc(4+payloadLength);
  header.writeUInt32LE(payloadLength,0);
  header.writeUInt32LE(json.length,4);
  json.copy(header,8);
  const first=Buffer.alloc(8);first.writeUInt32LE(4,0);first.writeUInt32LE(header.length,4);
  fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,Buffer.concat([first,header,...data]));
  return output;
}
