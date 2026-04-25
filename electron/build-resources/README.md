# Electron build resources

This directory holds the platform-specific installer assets. **None of the
binary assets below are checked in yet** — the paths are referenced by
`electron-builder.yml` so a packaging PR can drop them in without further
config changes.

Expected files (to be produced by the branding / design pass):

| File           | Use                             | Format                     |
|----------------|---------------------------------|----------------------------|
| `icon.ico`     | Windows installer + window icon | `.ico`, 256×256 multi-res  |
| `icon.icns`    | macOS DMG + dock icon           | `.icns`                    |
| `icon.png`     | Linux AppImage                  | 512×512 PNG                |
| `entitlements.mac.plist` | macOS hardened-runtime  | plist                      |
| `installer.nsh`| Optional NSIS customisation     | NSIS include file          |

Generate multi-res `icon.ico` with e.g.
`icon-gen -i brand/icon-1024.png -o electron/build-resources/icon.ico`.

Until these exist, `electron-builder` will fall back to its default electron
icon and emit a warning — the installer still builds and runs.
