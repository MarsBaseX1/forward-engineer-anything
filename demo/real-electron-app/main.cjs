const {app,BrowserWindow} = require('electron');
const fs=require('node:fs');
const path=require('node:path');
const smoke=process.argv.includes('--fea-smoke');
const marker='FEA_PACKAGED_GUI_OK';
let completed=false;
function finish(ok,reason){
  if(completed)return;
  completed=true;
  if(smoke){
    const file=process.env.FEA_SMOKE_REPORT;
    if(file && path.isAbsolute(file)){
      try{fs.writeFileSync(file,JSON.stringify({formatVersion:1,ok,reason:ok?'page-loaded':reason,platform:process.platform,appVersion:app.getVersion(),marker:ok?marker:null})+'\n',{flag:'wx',mode:0o600});}
      catch{ok=false;}
    } else ok=false;
    app.exit(ok?0:1);
  }
}
app.whenReady().then(()=>{
  const win=new BrowserWindow({width:640,height:400,show:true,webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true}});
  if(smoke){
    const watchdog=setTimeout(()=>finish(false,'page-timeout'),15000);
    watchdog.unref();
    win.webContents.once('did-fail-load',()=>finish(false,'load-failed'));
    win.webContents.once('did-finish-load',async()=>{
      try{
        const value=await win.webContents.executeJavaScript('document.getElementById("fea-smoke-marker")?.textContent');
        finish(value===marker,value===marker?'page-loaded':'marker-missing');
      }catch{finish(false,'dom-check-failed');}
    });
  }
  win.loadFile(path.join(__dirname,'index.html')).catch(()=>finish(false,'load-rejected'));
}).catch(()=>finish(false,'electron-ready-failed'));
app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit();});
