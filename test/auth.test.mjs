import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthorizationService} from '../src/auth-demo.mjs';
async function setup(t,clock=()=>1000){const service=createAuthorizationService({now:clock});const url=await service.listen();t.after(()=>service.close());return {service,url};}
async function perform(url,token,payload){const r=await fetch(url+'/perform',{method:'POST',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},body:JSON.stringify(payload)});return {status:r.status,body:await r.json()};}
const task={tenantId:'tenant-a',resourceId:'resource-a',action:'read'};
test('server authorizes only the stored tenant/resource/action, not client role flags',async t=>{
 const {service,url}=await setup(t);const token=service.issueGrant({subject:'alice',...task,expiresAtMs:5000,quota:2});
 assert.equal((await perform(url,token,{...task,isPremium:true,subject:'admin'})).body.subject,'alice');
 assert.equal((await perform(url,token,{...task,tenantId:'tenant-b'})).status,403);
 assert.equal((await perform(url,token,{...task,resourceId:'resource-b'})).status,403);
 assert.equal((await perform(url,token,{...task,action:'write'})).status,403);
 assert.equal((await perform(url,token,{...task})).status,200);
 assert.equal((await perform(url,token,{...task})).status,429);
 assert.equal((await perform(url,null,task)).status,401);
 assert.equal((await perform(url,'invalid-invalid-invalid-invalid-invalid-invalid',task)).status,401);
});
test('revocation and expiry independently fail closed',async t=>{
 let now=1000;const {service,url}=await setup(t,()=>now);
 const token=service.issueGrant({subject:'bob',...task,expiresAtMs:2000,quota:3});
 assert.equal((await perform(url,token,task)).status,200);
 now=2000;assert.equal((await perform(url,token,task)).status,403);
 now=1000;assert.equal(service.revoke(token),true);
 assert.equal((await perform(url,token,task)).body.reason,'revoked');
 assert.throws(()=>service.issueGrant({subject:'bob',...task,expiresAtMs:900,quota:3}),/AUTH_GRANT_INVALID/);
});
test('oversized or malformed input never spends quota',async t=>{
 const {service,url}=await setup(t),token=service.issueGrant({subject:'bob',...task,expiresAtMs:2000,quota:1});
 const tooBig=await perform(url,token,{...task,padding:'z'.repeat(10000)});assert.equal(tooBig.status,413);
 assert.equal((await perform(url,token,task)).status,200);
});
