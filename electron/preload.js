/**
 * Preload script — runs with Node enabled but the renderer isolated.
 *
 * Exposes a minimal, typed API on `window.aegir`. Everything else the
 * renderer wants to do must go through the normal HTTP surface served by the
 * FastAPI backend (which is itself guarded by JWT auth).
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegir', {
  /** Returns the local backend URL, e.g. "http://127.0.0.1:58123". */
  getBackendUrl: () => ipcRenderer.invoke('aegir:getBackendUrl'),

  /** Returns build/runtime metadata for the About dialog + crash reports. */
  getAppInfo: () => ipcRenderer.invoke('aegir:getAppInfo'),
});
