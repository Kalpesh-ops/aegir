const { app, BrowserWindow, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

// CRITICAL FIX 1: Disable sandbox to allow Admin rights for Scapy/TShark without crashing Chromium
app.commandLine.appendSwitch('no-sandbox');

let mainWindow, backendProcess, frontendProcess;
const isProd = app.isPackaged;
const resourcesPath = isProd ? process.resourcesPath : path.join(__dirname, '..');

// Start Python Backend
function startBackend() {
  const exe = isProd ? path.join(resourcesPath, 'backend', 'netsec-backend.exe') 
                     : path.join(__dirname, '..', 'dist', 'netsec-backend', 'netsec-backend.exe');
  backendProcess = spawn(exe, [], { 
      cwd: path.dirname(exe), // <--- ADD THIS
      windowsHide: true 
  });
}

// Add fs to your imports at the top if it isn't there:
// const fs = require('fs');

// Start Next.js Frontend
function startFrontend() {
  const frontendDir = isProd ? path.join(resourcesPath, 'frontend')
                             : path.join(__dirname, '..', 'frontend', '.next', 'standalone');
  const serverJs = path.join(frontendDir, 'server.js');
  
  // BYPASS: Rename the hidden 'bundled_modules' back to 'node_modules' on first launch
  const fs = require('fs');
  const bundledModules = path.join(frontendDir, 'bundled_modules');
  const nodeModules = path.join(frontendDir, 'node_modules');
  
  try {
    if (fs.existsSync(bundledModules)) {
      fs.renameSync(bundledModules, nodeModules);
      console.log("Restored node_modules successfully.");
    }
  } catch (e) {
    console.error("Failed to restore node_modules:", e);
  }

  // CRITICAL: Use process.execPath and ELECTRON_RUN_AS_NODE 
  // This uses Electron's internal Node engine so the user doesn't need to install Node.js!
  frontendProcess = spawn(process.execPath, [serverJs], {
    cwd: frontendDir,
    env: {
      ...process.env,
      PORT: '3000',
      HOSTNAME: '127.0.0.1',
      ELECTRON_RUN_AS_NODE: '1',
      NEXT_PUBLIC_API_URL: 'http://127.0.0.1:8000'
    },
    windowsHide: true,
  });
}

// Add dialog to your imports at the top if it isn't there:
// const { app, BrowserWindow, dialog } = require('electron');

function waitForPort(port, name, retries = 30, delay = 1000) {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    function check() {
      const req = http.get(`http://localhost:${port}`, (res) => {
        resolve(); 
      });
      req.on('error', () => {
        if (++attempts >= retries) {
            reject(new Error(`Timeout: ${name} (Port ${port}) failed to start.`));
        } else {
            setTimeout(check, delay);
        }
      });
      req.end();
    }
    check();
  });
}

app.whenReady().then(async () => {
  try {
    startBackend();
    startFrontend();
    
    // Catch child process errors and print them
    backendProcess.stderr.on('data', (data) => console.error(`Backend Error: ${data}`));
    frontendProcess.stderr.on('data', (data) => console.error(`Frontend Error: ${data}`));

    // Wait for both with a strict timeout
    await Promise.all([
      waitForPort(8000, "Python Backend"), 
      waitForPort(3000, "Next.js Frontend")
    ]);

    mainWindow = new BrowserWindow({
      width: 1280, height: 800,
      webPreferences: { nodeIntegration: false, contextIsolation: true }
    });
    mainWindow.setMenu(null);
    mainWindow.loadURL('http://localhost:3000');
    
    if (isProd) {
      autoUpdater.checkForUpdatesAndNotify();
    }

  } catch (error) {
    // IF ANYTHING FAILS, SHOW A MASSIVE ERROR BOX INSTEAD OF HANGING
    dialog.showErrorBox("Startup Error", error.message + "\n\nPlease check the logs.");
    app.quit();
  }
});

// CRITICAL FIX 2: Prevent Zombie Processes
app.on('before-quit', () => {
  if (process.platform === 'win32') {
    if (backendProcess) spawn('taskkill', ['/pid', backendProcess.pid, '/f', '/t']);
    if (frontendProcess) spawn('taskkill', ['/pid', frontendProcess.pid, '/f', '/t']);
  } else {
    backendProcess?.kill();
    frontendProcess?.kill();
  }
});

// --- Auto-Updater Events ---
autoUpdater.on('update-available', () => {
  dialog.showMessageBox({ type: 'info', title: 'Update Available', message: 'A new version is downloading in the background.' });
});
autoUpdater.on('update-downloaded', () => {
  dialog.showMessageBox({
    type: 'info', buttons: ['Restart', 'Later'], title: 'Application Update',
    message: 'Update downloaded. Restart the application to apply the updates.'
  }).then((result) => {
    if (result.response === 0) autoUpdater.quitAndInstall();
  });
});