/**
 * electron-updater bootstrap.
 *
 * Wired against the feed declared in `electron-builder.yml` (default: GitHub
 * Releases for this repository). Safe to call even before the release feed
 * is populated — errors are logged and swallowed so a user without an update
 * source never sees a broken window.
 *
 * Staged-rollout and `minSupportedVersion` support come for free with
 * electron-updater's `app-update.yml`; this module just forwards user-visible
 * state to the renderer so the UI can show an "Update available" toast.
 */

'use strict';

const { autoUpdater } = require('electron-updater');

function setupAutoUpdater({ log, window }) {
  autoUpdater.logger = log;
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  // On Windows + macOS updates are downloaded into a system cache; nothing
  // for us to do beyond configuring this flag.

  const forward = (channel, payload) => {
    if (window && !window.isDestroyed()) {
      window.webContents.send(channel, payload);
    }
  };

  autoUpdater.on('checking-for-update', () => {
    log.info('Checking for update…');
    forward('netsec:update', { state: 'checking' });
  });

  autoUpdater.on('update-available', (info) => {
    log.info('Update available:', info && info.version);
    forward('netsec:update', { state: 'available', version: info && info.version });
  });

  autoUpdater.on('update-not-available', (info) => {
    log.info('No update available (current=%s).', info && info.version);
    forward('netsec:update', { state: 'current', version: info && info.version });
  });

  autoUpdater.on('error', (err) => {
    log.warn('Updater error:', err && err.message ? err.message : err);
    forward('netsec:update', { state: 'error', message: err && err.message });
  });

  autoUpdater.on('download-progress', (progress) => {
    forward('netsec:update', {
      state: 'downloading',
      percent: progress.percent,
      bytesPerSecond: progress.bytesPerSecond,
    });
  });

  autoUpdater.on('update-downloaded', (info) => {
    log.info('Update downloaded; will install on next quit.');
    forward('netsec:update', { state: 'ready', version: info && info.version });
  });

  // Kick off the first check a few seconds after boot so we don't compete
  // with the initial scan / page load.
  setTimeout(() => {
    autoUpdater.checkForUpdatesAndNotify().catch((err) => {
      log.warn('Initial update check failed:', err && err.message);
    });
  }, 10_000);

  // Recheck every 4 hours for long-running sessions.
  setInterval(() => {
    autoUpdater.checkForUpdatesAndNotify().catch((err) => {
      log.warn('Periodic update check failed:', err && err.message);
    });
  }, 4 * 60 * 60 * 1000);
}

module.exports = { setupAutoUpdater };
