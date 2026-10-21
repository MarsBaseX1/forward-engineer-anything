import {createAuthorizationService} from '../src/auth-demo.mjs';
const auth=createAuthorizationService();
const address=await auth.listen();
const token=auth.issueGrant({subject:'demo-alice',tenantId:'team-a',resourceId:'sample',action:'read',expiresAtMs:Date.now()+60000,quota:1});
try {
 const response=await fetch(address+'/perform',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({tenantId:'team-a',resourceId:'sample',action:'read',premium:true})});
 const body=await response.json();
 if(response.status!==200 || body.subject!=='demo-alice')throw Error('AUTH_DEMO_FAILED');
 const reject=await fetch(address+'/perform',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({tenantId:'another-team',resourceId:'sample',action:'read'})});
 if(reject.status!==403)throw Error('AUTH_DEMO_TENANT_BOUNDARY_FAILED');
 console.log('AUTH DEMO PASS: authorized tenant accepted; cross-tenant access denied; token never printed.');
}finally {await auth.close()}
