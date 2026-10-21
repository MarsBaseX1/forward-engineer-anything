import http from 'node:http';
import crypto from 'node:crypto';

// Learning/reference service only. Local bind, in-memory capabilities; NO token issuance HTTP endpoint.
// Production systems should use established auth providers, durable revocation and shared quotas.
const MAX_BODY=8192;
const id=/^[A-Za-z0-9._-]{1,80}$/;
const digest=t=>crypto.createHash('sha256').update(t).digest('hex');
const reply=(res,status,data)=>{
  res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(JSON.stringify(data));
};
export function createAuthorizationService({now=Date.now}={}){
  const grants=new Map();
  function issueGrant({subject,tenantId,resourceId,action,expiresAtMs,quota}){
    if(![subject,tenantId,resourceId,action].every(v=>typeof v==='string' && id.test(v)) ||
       !Number.isSafeInteger(expiresAtMs) || expiresAtMs<=now() ||
       !Number.isSafeInteger(quota) || quota<1 || quota>1000)throw Error('AUTH_GRANT_INVALID');
    const token=crypto.randomBytes(32).toString('base64url');
    grants.set(digest(token),{subject,tenantId,resourceId,action,expiresAtMs,quota,used:0,revoked:false});
    return token;
  }
  function revoke(token){const row=grants.get(digest(token));if(!row)return false;row.revoked=true;return true;}
  async function handler(req,res){
    if(req.method!=='POST'||req.url!=='/perform')return reply(res,404,{ok:false,reason:'not-found'});
    const match=/^Bearer ([A-Za-z0-9_-]{30,})$/.exec(req.headers.authorization??'');
    if(!match)return reply(res,401,{ok:false,reason:'authentication-required'});
    const grant=grants.get(digest(match[1]));
    if(!grant)return reply(res,401,{ok:false,reason:'invalid-token'});
    if(grant.revoked)return reply(res,403,{ok:false,reason:'revoked'});
    if(now()>=grant.expiresAtMs)return reply(res,403,{ok:false,reason:'expired'});
    let buffer='';
    try{
      for await(const chunk of req){buffer+=chunk.toString('utf8');if(Buffer.byteLength(buffer)>MAX_BODY)return reply(res,413,{ok:false,reason:'too-large'});}
      const payload=JSON.parse(buffer);
      if(!payload || typeof payload!=='object' || ![payload.tenantId,payload.resourceId,payload.action].every(v=>typeof v==='string'&&id.test(v)))return reply(res,400,{ok:false,reason:'bad-request'});
      // Requested claims never override the independently stored server-side grant.
      if(payload.tenantId!==grant.tenantId || payload.resourceId!==grant.resourceId || payload.action!==grant.action)return reply(res,403,{ok:false,reason:'forbidden'});
      if(grant.used>=grant.quota)return reply(res,429,{ok:false,reason:'quota-exceeded'});
      grant.used++;
      return reply(res,200,{ok:true,subject:grant.subject,operation:'authorized-demo-operation',remaining:grant.quota-grant.used});
    }catch{return reply(res,400,{ok:false,reason:'bad-json'});}
  }
  const server=http.createServer(handler);
  server.requestTimeout=10000;
  return {issueGrant,revoke,server,listen:async()=>{
    await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
    return `http://127.0.0.1:${server.address().port}`;
  },close:async()=>new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))};
}
