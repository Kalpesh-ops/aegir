/**
 * Supervises the bundled Next.js standalone server in packaged mode.
 *
 * In dev we short-circuit and let the main process talk directly to
 * `next dev` — this module is only engaged when `app.isPackaged` is true.
 *
 * The packaged server is produced by `next build` with `output: 'standalone'`
 * (already configured in frontend/next.config.js). The electron-builder
 * `extraResources` entry copies `.next/standalone` + `public` + static assets
 * into `resources/frontend/`. At runtime we spawn Node + `server.js` with a
 * free port and `NEXT_PUBLIC_API_URL` pointed at the freshly-bound backend.
 */

'use strict';

const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const { app } = require('electron');

function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function startFrontendServer({ isDev, backendUrl, log }) {
  if (isDev) {
    log.info('Dev mode — skipping packaged frontend server.');
    return null;
  }

  const resourcesRoot = path.join(process.resourcesPath, 'frontend');
  const serverEntry = path.join(resourcesRoot, 'server.js');
  if (!fs.existsSync(serverEntry)) {
    throw new Error(
      `Packaged Next server not found at ${serverEntry}. ` +
      'Did the frontend:build step run and did extraResources copy it? ' +
      'See docs/architecture/electron.md.',
    );
  }

  const port = await findFreePort();
  const env = {
    ...process.env,
    PORT: String(port),
    HOSTNAME: '127.0.0.1',
    NODE_ENV: 'production',
    NEXT_PUBLIC_API_URL: backendUrl,
  };

  log.info('Starting packaged Next server on port', port);
  const child = spawn(process.execPath, [serverEntry], {
    cwd: resourcesRoot,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (buf) => log.info('[frontend]', buf.toString().trimEnd()));
  child.stderr.on('data', (buf) => log.info('[frontend-err]', buf.toString().trimEnd()));

  const handle = { child, port, url: `http://127.0.0.1:${port}`, exited: false };

  child.on('exit', (code, signal) => {
    handle.exited = true;
    log.info(`Frontend exited code=${code} signal=${signal}`);
  });

  child.on('error', (err) => log.error('Frontend spawn error:', err.message));

  // Poll until the server responds so the main process can safely load the URL.
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (handle.exited) {
      throw new Error('Frontend process exited before becoming ready.');
    }
    const ok = await probe(handle.url);
    if (ok) return handle;
    await sleep(250);
  }
  throw new Error(`Frontend did not become ready within 20s at ${handle.url}`);
}

async function resolveFrontendUrl(handle) {
  if (handle && handle.url) return handle.url;
  // Fallback: respect an explicit override (e.g. CI end-to-end tests).
  return process.env.NETSEC_FRONTEND_URL || 'http://127.0.0.1:3000';
}

function probe(url) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: 1500 }, (res) => {
      res.resume();
      // Any HTTP response (even a 404) means the server bound; good enough.
      resolve(res.statusCode < 500);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function stopFrontendServer(handle, { log } = {}) {
  if (!handle || handle.exited) return;
  const { child } = handle;
  log && log.info('Stopping frontend pid=', child.pid);
  try {
    if (process.platform === 'win32') {
      const { spawnSync } = require('node:child_process');
      spawnSync('taskkill', ['/pid', String(child.pid), '/f', '/t'], { windowsHide: true });
    } else {
      child.kill('SIGTERM');
    }
  } catch (err) {
    log && log.warn('Frontend stop error:', err.message);
  }
  await new Promise((resolve) => {
    const to = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { /* noop */ }
      resolve();
    }, 3000);
    child.once('exit', () => {
      clearTimeout(to);
      resolve();
    });
  });
}

module.exports = { startFrontendServer, stopFrontendServer, resolveFrontendUrl };
