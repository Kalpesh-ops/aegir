# Electron Desktop Shell — Architecture

This document describes how NetSec AI Scanner is packaged as a desktop
application (Windows `.exe` primarily, macOS and Linux best-effort).

> **Status:** Shell scaffold landed. Python bundling via PyInstaller and
> Windows EV code-signing are **tracked as follow-up PRs** and are NOT
> required to use the dev workflow below.

---

## Three-process model

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Electron main process                        │
│  electron/main.js                                                   │
│                                                                     │
│   ├── electron/backend-supervisor.js                                │
│   │       spawns:  python server.py   (dev)                         │
│   │              / netsec-backend.exe (packaged)                    │
│   │       env:     NETSEC_BIND_HOST=127.0.0.1                       │
│   │                NETSEC_BIND_PORT=<free port>                     │
│   │                                                                 │
│   ├── electron/frontend-supervisor.js   (packaged only)             │
│   │       spawns:  node resources/frontend/server.js                │
│   │       env:     PORT=<free port>                                 │
│   │                NEXT_PUBLIC_API_URL=http://127.0.0.1:<backend>   │
│   │                                                                 │
│   └── electron/auto-updater.js                                      │
│           checks:  GitHub Releases feed (electron-builder.yml)      │
│           cadence: on boot + every 4 h                              │
│                                                                     │
│   BrowserWindow loads:                                              │
│     dev       → http://127.0.0.1:3000   (next dev)                  │
│     packaged  → http://127.0.0.1:<frontend_port>                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Security posture

| Property                           | Value                                       |
|------------------------------------|---------------------------------------------|
| `contextIsolation`                 | **true**                                    |
| `nodeIntegration`                  | **false**                                   |
| `sandbox`                          | **true**                                    |
| `webSecurity`                      | **true**                                    |
| `devTools` (packaged)              | **false**                                   |
| Preload bridge                     | `window.netsec` (2 read-only RPCs)          |
| CSP                                | enforced in the main via `onHeadersReceived`|
| External navigation                | intercepted → system browser                |
| Backend bind host                  | `127.0.0.1` only                            |
| Frontend bind host                 | `127.0.0.1` only                            |

## Dev workflow

The dev-mode orchestrator spawns three processes side-by-side: the Python
backend, `next dev`, and Electron. All are supervised by `concurrently` with
colour-coded log streams.

```bash
# one-time
npm install
npm --prefix frontend install

# start everything
npm run dev
```

Individual moving parts:

```bash
# backend only (port 8000 unless NETSEC_BIND_PORT set)
python server.py

# next dev only
npm --prefix frontend run dev

# electron only (assumes the two above are running)
NETSEC_ELECTRON_DEV=1 npm run electron:start
```

## Packaged workflow (follow-up PR)

These steps **belong to the next packaging PR** — they're documented here so
the scaffold and the packaging PR stay consistent.

```
┌── frontend/.next/standalone/server.js ────────┐
│                                               │
│  (output: 'standalone' is already enabled in  │
│   frontend/next.config.js)                    │
│                                               │
└───────────────────────────────────────────────┘
           │                  │
           ▼                  │
  extraResources ──►          │
   frontend/ → resources/frontend/
                              │
                              ▼
┌── dist/backend/netsec-backend[.exe] ─────────┐
│                                              │
│  PyInstaller --onedir bundle of server.py    │
│  (tool choice & spec file TBD in next PR)    │
│                                              │
└──────────────────────────────────────────────┘
           │
           ▼
  extraResources ──►
   dist/backend → resources/backend/

Build artefacts under  dist-electron/
   • NetSec-AI-Scanner-Setup-<version>.exe   (Windows NSIS installer)
   • NetSec-AI-Scanner-<version>-mac.dmg     (macOS DMG)
   • NetSec-AI-Scanner-<version>.AppImage    (Linux AppImage)
```

Build commands (once PyInstaller wiring lands):

```bash
npm run frontend:build              # emits frontend/.next/standalone
# TODO: pyinstaller build step that emits dist/backend/netsec-backend[.exe]
npm run electron:build:win          # Windows installer
npm run electron:build:mac          # macOS DMG
npm run electron:build:linux        # Linux AppImage
```

## Auto-update

`electron-updater` reads the `publish` block in `electron-builder.yml` and
checks GitHub Releases for the latest `vX.Y.Z` tag on app start and every
four hours. The flow:

1. Background download into the OS cache.
2. `update-downloaded` event → renderer shows a toast.
3. On next app quit, the installer swaps the binary.

**Knobs (wire in as needed):**

- `autoUpdater.allowPrerelease = true` — opt into beta channel for testers.
- `autoUpdater.channel = 'beta'` — channel-based cohorting.
- `stagingPercentage` in the release's `latest.yml` — staged rollouts.
- `minSupportedVersion` — force-update older installs.

## Crash reporting

`electron-log` writes to the standard per-platform locations:

- **Windows**: `%USERPROFILE%\AppData\Roaming\netsec-ai-scanner\logs\main.log`
- **macOS**:   `~/Library/Logs/netsec-ai-scanner/main.log`
- **Linux**:   `~/.config/netsec-ai-scanner/logs/main.log`

Sentry or equivalent should be added in a future PR; the scaffold deliberately
doesn't bake in a vendor choice yet.

## Known follow-up work (tracked separately)

- [ ] PyInstaller build step producing a single-folder backend bundle.
- [ ] Runtime injection of `NEXT_PUBLIC_API_URL` so the client bundle can talk
      to the dynamically-bound backend port. Currently the packaged Next
      server uses `rewrites()` + env at server-startup time; the client bundle
      uses whatever `NEXT_PUBLIC_API_URL` was at build time. Recommended fix:
      move the two direct `${API_URL}/api/...` fetches in
      `frontend/app/dashboard/scan/page.jsx` and
      `frontend/app/dashboard/history/actions.js` to relative `/api/...`
      URLs, which funnel through the Next `rewrites()` path and always hit
      the right backend.
- [ ] Windows EV code-signing (requires the cert purchase).
- [ ] macOS notarisation (requires an Apple Developer account).
- [ ] Branded icons (`electron/build-resources/icon.{ico,icns,png}`).
- [ ] Sentry / equivalent crash reporting.
