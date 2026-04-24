/**
 * NetSec AI Scanner — Electron main process.
 *
 * Responsibilities:
 *   1. Start the Python FastAPI backend as a child process on a free
 *      loopback port.
 *   2. Poll `/health` until the backend is ready.
 *   3. In dev (NETSEC_ELECTRON_DEV=1) load `http://localhost:3000` (Next dev
 *      server); in packaged mode spawn the bundled Next standalone server and
 *      load its URL.
 *   4. Supervise both child processes and tear them down cleanly on quit.
 *   5. Wire electron-updater against a GitHub Releases feed (when the
 *      `publish` block of electron-builder.yml is populated).
 *
 * Security stance: contextIsolation ON, nodeIntegration OFF, no remote
 * module. The preload exposes a tiny typed surface on `window.netsec`.
 */

'use strict';

const { app, BrowserWindow, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const log = require('electron-log/main');

const { startBackend, stopBackend, waitForBackendReady } = require('./backend-supervisor');
const {
  startFrontendServer,
  stopFrontendServer,
  resolveFrontendUrl,
} = require('./frontend-supervisor');
const { setupAutoUpdater } = require('./auto-updater');

log.transports.file.level = 'info';
log.transports.console.level = 'info';

const IS_DEV = process.env.NETSEC_ELECTRON_DEV === '1';
const DEV_FRONTEND_URL = process.env.NETSEC_DEV_FRONTEND_URL || 'http://127.0.0.1:3000';

let mainWindow = null;
let backendHandle = null;
let frontendHandle = null;

async function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 620,
    backgroundColor: '#0b0b10',
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      // Block the renderer from opening dev-tools in packaged builds.
      devTools: IS_DEV,
    },
  });

  // Defence-in-depth CSP for the renderer. The Next server also sets its own
  // headers; this is the floor every document must meet.
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const csp = [
      "default-src 'self'",
      // Next ships small inline bootstrap scripts. 'unsafe-inline' here is
      // scoped to the packaged renderer only; not a network origin.
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      // The Electron app talks to our local FastAPI on 127.0.0.1 and to
      // Supabase over HTTPS. Nothing else.
      "connect-src 'self' http://127.0.0.1:* https://*.supabase.co https://*.supabase.in",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ');
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [csp],
      },
    });
  });

  // Hard-refuse any navigation away from the local renderer. Anything that
  // looks like a real web link should open in the user's system browser.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) {
      require('electron').shell.openExternal(url).catch((err) => {
        log.warn('Failed to open external URL:', err.message);
      });
    }
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, targetUrl) => {
    const parsed = new URL(targetUrl);
    const allowedHosts = new Set(['127.0.0.1', 'localhost']);
    if (!allowedHosts.has(parsed.hostname)) {
      event.preventDefault();
      require('electron').shell.openExternal(targetUrl).catch(() => {});
    }
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  const frontendUrl = IS_DEV ? DEV_FRONTEND_URL : await resolveFrontendUrl(frontendHandle);
  log.info('Loading renderer at', frontendUrl);
  await mainWindow.loadURL(frontendUrl);
}

async function bootstrap() {
  try {
    log.info('NetSec bootstrap starting (dev=%s)', IS_DEV);

    backendHandle = await startBackend({ isDev: IS_DEV, log });
    await waitForBackendReady(backendHandle, { timeoutMs: 30_000, log });
    log.info('Backend ready at', backendHandle.url);

    if (!IS_DEV) {
      frontendHandle = await startFrontendServer({
        isDev: IS_DEV,
        backendUrl: backendHandle.url,
        log,
      });
    }

    await createMainWindow();

    // Only wire auto-updates in packaged builds. Dev restarts would fight the
    // updater for the same exe path.
    if (!IS_DEV && app.isPackaged) {
      setupAutoUpdater({ log, window: mainWindow });
    }
  } catch (err) {
    log.error('Bootstrap failed:', err);
    // Show a native dialog rather than silently exiting so the user knows
    // why the window never appeared.
    const { dialog } = require('electron');
    dialog.showErrorBox(
      'NetSec failed to start',
      `${err && err.message ? err.message : err}\n\nSee logs at:\n${log.transports.file.getFile().path}`,
    );
    app.quit();
  }
}

// --- IPC surface kept deliberately small; see preload.js -------------------
const { ipcMain } = require('electron');

ipcMain.handle('netsec:getBackendUrl', () => {
  return backendHandle ? backendHandle.url : null;
});

ipcMain.handle('netsec:getAppInfo', () => {
  return {
    version: app.getVersion(),
    platform: process.platform,
    isDev: IS_DEV,
    logPath: log.transports.file.getFile().path,
  };
});

// --- App lifecycle ---------------------------------------------------------
app.whenReady().then(() => {
  bootstrap();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      bootstrap();
    }
  });
});

app.on('window-all-closed', () => {
  // On macOS apps typically stay running; on Windows / Linux quit.
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// --- Child-process teardown ------------------------------------------------
async function shutdownChildren() {
  try {
    if (frontendHandle) {
      await stopFrontendServer(frontendHandle, { log });
      frontendHandle = null;
    }
  } catch (err) {
    log.warn('Error stopping frontend:', err && err.message);
  }
  try {
    if (backendHandle) {
      await stopBackend(backendHandle, { log });
      backendHandle = null;
    }
  } catch (err) {
    log.warn('Error stopping backend:', err && err.message);
  }
}

app.on('before-quit', (event) => {
  if (backendHandle || frontendHandle) {
    event.preventDefault();
    shutdownChildren().finally(() => {
      app.quit();
    });
  }
});

process.on('SIGINT', () => app.quit());
process.on('SIGTERM', () => app.quit());
