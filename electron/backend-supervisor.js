/**
 * Supervises the FastAPI backend child process.
 *
 * Dev mode: launches `python server.py` with the repo root as the CWD and a
 * random free loopback port set via `NETSEC_BIND_PORT`.
 *
 * Packaged mode: expects a bundled backend binary (produced by a future
 * PyInstaller step) under `resources/backend/` and launches it the same way.
 * The binary path and argv are kept behind env overrides so the packaging PR
 * can wire in its final layout without touching this file.
 */

'use strict';

const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const { app } = require('electron');

const HEALTH_PATH = '/health';

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

function resolveBackendCommand(isDev) {
  // Explicit override for local testing / packaging experiments.
  const overridePath = process.env.NETSEC_BACKEND_BIN;
  if (overridePath) {
    return { command: overridePath, args: [], cwd: path.dirname(overridePath) };
  }

  if (isDev || !app.isPackaged) {
    const repoRoot = path.resolve(__dirname, '..');
    const pythonBin = process.env.NETSEC_PYTHON_BIN
      || (process.platform === 'win32' ? 'python' : 'python3');
    return {
      command: pythonBin,
      args: ['server.py'],
      cwd: repoRoot,
    };
  }

  // Packaged layout. The bundled binary is placed under resources/ by
  // electron-builder via the extraResources mapping in electron-builder.yml.
  const binName = process.platform === 'win32' ? 'aegir-backend.exe' : 'aegir-backend';
  const resourcesRoot = path.join(process.resourcesPath, 'backend');
  const candidate = path.join(resourcesRoot, binName);
  if (!fs.existsSync(candidate)) {
    throw new Error(
      `Packaged backend binary not found at ${candidate}. ` +
      'Did the PyInstaller step run? See docs/architecture/electron.md for the packaging flow.',
    );
  }
  return { command: candidate, args: [], cwd: resourcesRoot };
}

async function startBackend({ isDev, log }) {
  const port = Number(process.env.NETSEC_BIND_PORT || await findFreePort());
  const host = process.env.NETSEC_BIND_HOST || '127.0.0.1';

  const { command, args, cwd } = resolveBackendCommand(isDev);
  log.info('Starting backend:', command, args.join(' '), 'cwd=', cwd, 'port=', port);

  const env = {
    ...process.env,
    NETSEC_BIND_HOST: host,
    NETSEC_BIND_PORT: String(port),
    // Make Python output unbuffered so logs flush promptly.
    PYTHONUNBUFFERED: '1',
  };

  const child = spawn(command, args, {
    cwd,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', (buf) => log.info('[backend]', buf.toString().trimEnd()));
  child.stderr.on('data', (buf) => log.info('[backend-err]', buf.toString().trimEnd()));

  const handle = {
    child,
    url: `http://${host}:${port}`,
    host,
    port,
    exited: false,
  };

  child.on('exit', (code, signal) => {
    handle.exited = true;
    log.info(`Backend exited code=${code} signal=${signal}`);
  });

  child.on('error', (err) => {
    log.error('Backend spawn error:', err.message);
  });

  return handle;
}

async function waitForBackendReady(handle, { timeoutMs = 30_000, log }) {
  const start = Date.now();
  const healthUrl = `${handle.url}${HEALTH_PATH}`;
  let lastError = null;

  while (Date.now() - start < timeoutMs) {
    if (handle.exited) {
      throw new Error('Backend process exited before becoming healthy.');
    }
    try {
      const ok = await probe(healthUrl);
      if (ok) return true;
    } catch (err) {
      lastError = err;
    }
    await sleep(400);
  }
  throw new Error(
    `Backend did not become healthy within ${timeoutMs}ms at ${healthUrl}` +
    (lastError ? ` (last error: ${lastError.message})` : ''),
  );
}

function probe(url) {
  return new Promise((resolve) => {
    const http = require('node:http');
    const req = http.get(url, { timeout: 1500 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function stopBackend(handle, { log } = {}) {
  if (!handle || handle.exited) return;
  const { child } = handle;
  log && log.info('Stopping backend pid=', child.pid);
  try {
    if (process.platform === 'win32') {
      // `SIGTERM` on Windows is equivalent to kill; use taskkill for children.
      const { spawnSync } = require('node:child_process');
      spawnSync('taskkill', ['/pid', String(child.pid), '/f', '/t'], { windowsHide: true });
    } else {
      child.kill('SIGTERM');
    }
  } catch (err) {
    log && log.warn('Backend stop error:', err.message);
  }

  // Give it a moment to exit gracefully before force-killing.
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

module.exports = { startBackend, waitForBackendReady, stopBackend };
