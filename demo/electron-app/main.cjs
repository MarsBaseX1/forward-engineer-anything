const { app, BrowserWindow } = require('electron');
app.whenReady().then(() => {
  const window = new BrowserWindow({width: 700, height: 420, webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true}});
  window.loadFile('index.html');
});
app.on('window-all-closed', () => {if(process.platform!=='darwin') app.quit();});
