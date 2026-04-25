# Electron Desktop Shell — Architecture

This document describes how Aegir is packaged as a desktop
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
│   │              / aegir-backend.exe (packaged)                    │
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
| Preload bridge                     | `window.aegir` (2 read-only RPCs)          |
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
┌── dist/backend/aegir-backend[.exe] ─────────┐
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
   • Aegir-Setup-<version>.exe   (Windows NSIS installer)
   • Aegir-<version>-mac.dmg     (macOS DMG)
   • Aegir-<version>.AppImage    (Linux AppImage)
```

Build commands (once PyInstaller wiring lands):

```bash
npm run frontend:build              # emits frontend/.next/standalone
# TODO: pyinstaller build step that emits dist/backend/aegir-backend[.exe]
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

- **Windows**: `%USERPROFILE%\AppData\Roaming\aegir\logs\main.log`
- **macOS**:   `~/Library/Logs/aegir/main.log`
- **Linux**:   `~/.config/aegir/logs/main.log`

Sentry or equivalent should be added in a future PR; the scaffold deliberately
doesn't bake in a vendor choice yet.

## Building a Windows installer end-to-end

Three commands in order; each step's output feeds the next via the
`extraResources` mappings declared in `electron-builder.yml`.

```bash
# 1. Backend → single-folder bundle at dist/aegir-backend/aegir-backend.exe
pyinstaller aegir-backend.spec

# 2. Frontend → Next standalone bundle at frontend/.next/standalone/
cd frontend
npm ci
npm run build
cd ..

# 3. Electron installer → dist-electron/Aegir Setup-<ver>.exe
npm ci
npx electron-builder --win nsis
```

The PyInstaller spec is at `aegir-backend.spec` (committed). Hidden
imports there cover uvicorn lifespan/protocols, scapy, google-generativeai,
httpx (used by the dependency installer), and the `nmap` python package.

> **Privileged install on Windows.** The NSIS installer marks the app as
> `requestedExecutionLevel: requireAdministrator`. Scapy + TShark live
> capture needs WinPcap raw-socket access which won't work without admin.
> Trade-off: every renderer feature inherits admin rights for the lifetime
> of the launch. The dependency-installer flow (`/dashboard/setup`) is the
> beachhead for migrating to per-process elevation later — Nmap/TShark
> sub-processes can be elevated individually via UAC at scan time, while
> the Electron UI itself runs as a regular user.

> **The `bundled_modules → node_modules` rename.** electron-builder 26 has a
> long-running quirk where `node_modules` directories listed in
> `extraResources` get partially stripped during signing on some platforms.
> The Next standalone payload is shipped under the name `bundled_modules`
> instead, and the supervisor renames it on first launch. See
> `electron/frontend-supervisor.js` for the migration code.

## Known follow-up work (tracked separately)

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
- [ ] Per-process UAC elevation for nmap/tshark sub-processes (replacing the
      whole-app `requireAdministrator` model).
